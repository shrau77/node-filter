package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
	goproxy "golang.org/x/net/proxy"
)

const (
	WorkerCount    = 20
	MinPortRange   = 20000
	MaxPortRange   = 35000
	XrayURL        = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
	SingBoxURL     = "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-1.10.0-linux-amd64.tar.gz"
	GeoIPURL       = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
	RemoteSNIURL   = "https://raw.githubusercontent.com/shrau77/zhopa-bobra/main/results/elite_sni.txt"
	SpeedTestURL   = "https://speed.cloudflare.com/__down?bytes=2097152"
	SpeedTestSize  = 1 * 1024 * 1024
	TimeoutCheck   = 5 * time.Second
	TimeoutSpeed   = 10 * time.Second
	UltraFastSpeed = 3.5
	FastSpeed      = 2.5
)

// === ЗАБАНЕННЫЕ TLD (Иран, Китай и прочий мусор) ===
var BannedTLDs = []string{
	".ir", ".cn", ".pk", ".af", ".sy", ".sa", ".vn", ".th", ".id",
	".br", ".ng", ".bd", ".ye", ".mn", ".kh", ".et", ".ar", ".in",
	".kp", ".hk", ".tw", ".win", ".top", ".shop", ".icu", ".online",
	".xyz", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq",
}

// === ЗАБАНЕННЫЕ ПАТТЕРНЫ В SNI (Иранский мусор, DDNS, Free VPN) ===
var BannedPatterns = []string{
	// Иранские провайдеры
	"iran", "mokhaberat", "pars", "asiatech", "mcci", "pgi",
	"dpnet", "shatel", "hiweb", "irancell",
	// Китай
	"alibaba", "tencent", "huawei",
	// Мусорные паттерны
	"free", "trial", "test", "demo", "vpnfree", "freevpn",
	"proxy", "vpns", "trojan", "v2ray", "xray",
	// Динамические DNS (часто используются в мусорных нодах)
	"duckdns", "no-ip", "ddns", "dyndns", "servebeer",
	"serveftp", "servehttp", "myftp", "zapto", "sytes",
	"redirectme", "chickenkiller", "crabdance", "crapouille",
	// Подозрительные
	"node", "server", "config", "vpn-", "-vpn",
}

// === СТРАНЫ-ИСТОЧНИКИ МУСОРА ===
var BannedCountries = map[string]bool{
	"IR": true, // Иран
	"CN": true, // Китай
	"PK": true, // Пакистан
	"AF": true, // Афганистан
	"NG": true, // Нигерия
	"BD": true, // Бангладеш
}

// === ДОПУСТИМЫЕ ПОРТЫ ДЛЯ TROJAN/HYSTERIA2/TUIC ===
var TrojanValidPorts = map[int]bool{443: true, 2053: true, 2083: true, 2087: true, 2096: true, 8443: true, 10443: true}
var Hysteria2ValidPorts = map[int]bool{443: true, 8443: true, 10443: true, 14443: true}
var TUICValidPorts = map[int]bool{443: true, 8443: true}

var testURLs = []string{
	"http://gstatic.com/generate_204",
	"http://cp.cloudflare.com/generate_204",
	"http://www.google.com/generate_204",
	"http://clients4.google.com/generate_204",
	"http://www.gstatic.com/generate_204",
}

var fingerprints = []string{
	"chrome", "firefox", "safari", "edge", "ios", "android", "random", "randomized",
}

var spiderXPaths = []string{
	"/", "/index.html", "/home", "/api/v1", "/static/main.js",
	"/assets/bundle.css", "/images/logo.png", "/fonts/roboto.woff2",
	"/manifest.json", "/sw.js", "/favicon.ico", "/robots.txt", "/sitemap.xml",
}

var (
	debugMode   bool
	verboseMode bool
	debugFile   *os.File
	debugCount  int32
	debugLimit  int32 = 30

	countryFlags = map[string]string{
		"US": "🇺🇸", "GB": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "NL": "🇳🇱",
		"CA": "🇨🇦", "JP": "🇯🇵", "KR": "🇰🇷", "SG": "🇸🇬", "HK": "🇭🇰",
		"TW": "🇹🇼", "AU": "🇦🇺", "RU": "🇷🇺", "CN": "🇨🇳", "IN": "🇮🇳",
		"BR": "🇧🇷", "TR": "🇹🇷", "SE": "🇸🇪", "PL": "🇵🇱", "IT": "🇮🇹",
		"ES": "🇪🇸", "CH": "🇨🇭", "FI": "🇫🇮", "NO": "🇳🇴", "DK": "🇩🇰",
	}

	statsTotalInput    int32
	statsParseFailed   int32
	statsNoSNI         int32
	statsSNIRejected   int32
	statsBannedTLD     int32
	statsBannedPattern int32
	statsBannedCountry int32
	statsInvalidPort   int32
	statsConfigFailed  int32
	statsConnectFailed int32
	statsSpeedFailed   int32
	statsSuccess       int32
)

type ProxyNode struct {
	RawLink  string
	Protocol string
	Address  string
	Port     int
	Name     string
	Config   map[string]interface{}
}

type CheckResult struct {
	Node      *ProxyNode
	Speed     float64
	CountryID string
	Success   bool
}

type XrayConfig struct {
	Log       map[string]interface{}   `json:"log"`
	Inbounds  []map[string]interface{} `json:"inbounds"`
	Outbounds []map[string]interface{} `json:"outbounds"`
}

type SingBoxConfig struct {
	Log       map[string]interface{}   `json:"log"`
	Inbounds  []map[string]interface{} `json:"inbounds"`
	Outbounds []map[string]interface{} `json:"outbounds"`
}

var geoIPReader *geoip2.Reader
var portCounter int32 = MinPortRange
var sniWhitelist []string

func init() {
	rand.Seed(time.Now().UnixNano())
}

func randomFingerprint() string {
	return fingerprints[rand.Intn(len(fingerprints))]
}

func randomSpiderX() string {
	return spiderXPaths[rand.Intn(len(spiderXPaths))]
}

func randomTestURL() string {
	return testURLs[rand.Intn(len(testURLs))]
}

// === SNI FILTERING ===

func isBannedTLD(sni string) bool {
	sniLower := strings.ToLower(sni)
	for _, tld := range BannedTLDs {
		if strings.HasSuffix(sniLower, tld) {
			return true
		}
	}
	return false
}

func hasBannedPattern(sni string) bool {
	sniLower := strings.ToLower(sni)
	for _, pattern := range BannedPatterns {
		if strings.Contains(sniLower, pattern) {
			return true
		}
	}
	return false
}

func isTargetSNI(nodeSNI string, whitelist []string) bool {
	if nodeSNI == "" {
		return false
	}
	nodeSNILower := strings.ToLower(nodeSNI)
	for _, suffix := range whitelist {
		suffixLower := strings.ToLower(suffix)
		if strings.HasSuffix(nodeSNILower, "."+suffixLower) || nodeSNILower == suffixLower {
			return true
		}
	}
	return false
}

func isValidPort(protocol string, port int) bool {
	switch protocol {
	case "trojan":
		return TrojanValidPorts[port]
	case "hysteria2":
		return Hysteria2ValidPorts[port]
	case "tuic":
		return TUICValidPorts[port]
	default:
		return true // VLESS, SS - любой порт
	}
}

func main() {
	fmt.Println("🚀 Starting L7 Proxy Checker (Anti-Iran Edition)")
	fmt.Println("=================================================")

	inputFile := flag.String("input", "proxies.txt", "Path to input proxy list")
	whitelistFile := flag.String("whitelist", "whitelist.txt", "Path to SNI whitelist")
	flag.BoolVar(&debugMode, "debug", false, "Enable debug logging")
	flag.BoolVar(&verboseMode, "verbose", false, "Enable verbose output")
	flag.Parse()

	if debugMode {
		var err error
		debugFile, err = os.Create("xray_debug.log")
		if err == nil {
			fmt.Println("📝 Debug mode enabled")
		}
	}
	if verboseMode {
		fmt.Println("🔊 Verbose mode enabled")
	}

	if err := setupDependencies(); err != nil {
		fmt.Printf("❌ Failed to setup dependencies: %v\n", err)
		os.Exit(1)
	}

	var err error
	geoIPReader, err = geoip2.Open("GeoLite2-Country.mmdb")
	if err != nil {
		fmt.Printf("❌ Failed to open GeoIP: %v\n", err)
		os.Exit(1)
	}
	defer geoIPReader.Close()

	// Загружаем whitelist
	sniWhitelist, err = readSNIWhitelist(*whitelistFile)
	if err != nil {
		fmt.Printf("⚠️ Could not read local whitelist: %v\n", err)
	}

	// Загружаем удалённый SNI
	remoteSNI, err := fetchRemoteSNI()
	if err == nil && len(remoteSNI) > 0 {
		sniWhitelist = append(sniWhitelist, remoteSNI...)
		fmt.Printf("📋 Loaded %d SNI from remote + %d local = %d total\n", 
			len(remoteSNI), len(sniWhitelist)-len(remoteSNI), len(sniWhitelist))
	} else {
		fmt.Printf("📋 Loaded %d SNI from local file\n", len(sniWhitelist))
	}

	// Считаем строки
	file, _ := os.Open(*inputFile)
	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
	}
	file.Close()

	fmt.Printf("📄 Input file: %d lines\n", lineCount)
	statsTotalInput = int32(lineCount)

	nodes, err := readProxyList(*inputFile)
	if err != nil {
		fmt.Printf("❌ Failed to read proxy list: %v\n", err)
		os.Exit(1)
	}

	statsParseFailed = statsTotalInput - int32(len(nodes))
	fmt.Printf("📋 Parsed: %d nodes, Failed: %d\n", len(nodes), statsParseFailed)

	results := processNodes(nodes)
	saveResults(results)

	// Статистика
	fmt.Println("\n=================================================")
	fmt.Println("📊 FINAL STATISTICS:")
	fmt.Printf("   📥 Input:          %d\n", statsTotalInput)
	fmt.Printf("   ❌ Parse failed:   %d\n", statsParseFailed)
	fmt.Printf("   🚫 No SNI:         %d\n", statsNoSNI)
	fmt.Printf("   🔒 SNI rejected:   %d\n", statsSNIRejected)
	fmt.Printf("   🚫 Banned TLD:     %d\n", statsBannedTLD)
	fmt.Printf("   🚫 Banned Pattern: %d\n", statsBannedPattern)
	fmt.Printf("   🚫 Banned Country: %d\n", statsBannedCountry)
	fmt.Printf("   🚫 Invalid Port:   %d\n", statsInvalidPort)
	fmt.Printf("   ⚙️ Config failed:   %d\n", statsConfigFailed)
	fmt.Printf("   🔌 Connect failed: %d\n", statsConnectFailed)
	fmt.Printf("   🐌 Speed too low:  %d\n", statsSpeedFailed)
	fmt.Printf("   ✅ Success:        %d\n", statsSuccess)
	fmt.Println("=================================================")
}

func fetchRemoteSNI() ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(RemoteSNIURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var snis []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			snis = append(snis, line)
		}
	}
	return snis, nil
}

func setupDependencies() error {
	// Xray
	if _, err := os.Stat("xray"); os.IsNotExist(err) {
		fmt.Println("📥 Downloading Xray Core...")
		if err := downloadFile("xray.zip", XrayURL); err != nil {
			return err
		}
		exec.Command("unzip", "-o", "xray.zip", "xray").Run()
		os.Chmod("xray", 0755)
		os.Remove("xray.zip")
	}

	// Sing-box (для Hysteria2/TUIC)
	if _, err := os.Stat("sing-box"); os.IsNotExist(err) {
		fmt.Println("📥 Downloading Sing-box...")
		if err := downloadFile("sing-box.tar.gz", SingBoxURL); err != nil {
			return err
		}
		exec.Command("tar", "-xzf", "sing-box.tar.gz").Run()
		// Ищем бинарник
		exec.Command("sh", "-c", "mv sing-box-*/sing-box . 2>/dev/null || true").Run()
		os.Chmod("sing-box", 0755)
		os.Remove("sing-box.tar.gz")
	}

	// GeoIP
	if _, err := os.Stat("GeoLite2-Country.mmdb"); os.IsNotExist(err) {
		fmt.Println("📥 Downloading GeoIP...")
		if err := downloadFile("GeoLite2-Country.mmdb", GeoIPURL); err != nil {
			return err
		}
	}
	return nil
}

func downloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func readSNIWhitelist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var snis []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			snis = append(snis, strings.TrimPrefix(line, "."))
		}
	}
	return snis, scanner.Err()
}

func readProxyList(filename string) ([]*ProxyNode, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var nodes []*ProxyNode
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		node, err := parseProxyLink(line)
		if err != nil {
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes, scanner.Err()
}

func parseProxyLink(link string) (*ProxyNode, error) {
	linkLower := strings.ToLower(link)
	
	if strings.HasPrefix(linkLower, "vless://") {
		return parseVLESS(link)
	} else if strings.HasPrefix(linkLower, "trojan://") {
		return parseTrojan(link)
	} else if strings.HasPrefix(linkLower, "ss://") {
		return parseShadowsocks(link)
	} else if strings.HasPrefix(linkLower, "hysteria2://") || strings.HasPrefix(linkLower, "hy2://") {
		return parseHysteria2(link)
	} else if strings.HasPrefix(linkLower, "tuic://") {
		return parseTUIC(link)
	}
	return nil, fmt.Errorf("unsupported protocol")
}

func parseVLESS(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "vless", Config: make(map[string]interface{})}

	mainPart := link
	if idx := strings.Index(link, "#"); idx != -1 {
		mainPart = link[:idx]
		node.Name, _ = url.QueryUnescape(link[idx+1:])
	}

	re := regexp.MustCompile(`vless://([^@]+)@([^:]+):(\d+)/?\?(.+)$`)
	matches := re.FindStringSubmatch(mainPart)
	if len(matches) < 5 {
		return nil, fmt.Errorf("invalid vless link")
	}

	node.Config["uuid"] = matches[1]
	node.Address = matches[2]
	node.Port, _ = strconv.Atoi(matches[3])
	params := parseQueryParams(matches[4])

	netType := params.Get("type")
	if idx := strings.IndexAny(netType, "#&;"); idx != -1 {
		netType = netType[:idx]
	}
	netType = strings.TrimSpace(netType)
	if netType == "" {
		netType = "tcp"
	}

	node.Config["type"] = netType
	node.Config["security"] = params.Get("security")
	node.Config["encryption"] = params.Get("encryption")
	node.Config["flow"] = params.Get("flow")
	node.Config["sni"] = params.Get("sni")
	node.Config["fp"] = params.Get("fp")
	node.Config["pbk"] = params.Get("pbk")
	node.Config["sid"] = params.Get("sid")

	return node, nil
}

func parseTrojan(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "trojan", Config: make(map[string]interface{})}

	mainPart := link
	if idx := strings.Index(link, "#"); idx != -1 {
		mainPart = link[:idx]
		node.Name, _ = url.QueryUnescape(link[idx+1:])
	}

	re := regexp.MustCompile(`trojan://([^@]+)@([^:]+):(\d+)/?\?(.+)$`)
	matches := re.FindStringSubmatch(mainPart)
	if len(matches) < 5 {
		return nil, fmt.Errorf("invalid trojan link")
	}

	node.Config["password"] = matches[1]
	node.Address = matches[2]
	node.Port, _ = strconv.Atoi(matches[3])
	params := parseQueryParams(matches[4])

	netType := params.Get("type")
	if idx := strings.IndexAny(netType, "#&;"); idx != -1 {
		netType = netType[:idx]
	}
	if netType == "" {
		netType = "tcp"
	}

	node.Config["type"] = netType
	node.Config["sni"] = params.Get("sni")
	node.Config["security"] = params.Get("security")

	return node, nil
}

func parseShadowsocks(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "shadowsocks", Config: make(map[string]interface{})}

	link = strings.TrimPrefix(link, "ss://")
	parts := strings.Split(link, "#")
	if len(parts) > 1 {
		node.Name, _ = url.QueryUnescape(parts[1])
	}

	mainPart := parts[0]
	atParts := strings.Split(mainPart, "@")
	if len(atParts) < 2 {
		return nil, fmt.Errorf("invalid shadowsocks link")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(atParts[0])
	if err != nil {
		decoded, _ = base64.StdEncoding.DecodeString(atParts[0])
	}
	methodPass := strings.SplitN(string(decoded), ":", 2)
	if len(methodPass) == 2 {
		node.Config["method"] = methodPass[0]
		node.Config["password"] = methodPass[1]
	}

	serverPort := strings.Split(atParts[1], ":")
	if len(serverPort) < 2 {
		return nil, fmt.Errorf("invalid shadowsocks server:port")
	}
	node.Address = serverPort[0]
	node.Port, _ = strconv.Atoi(serverPort[1])

	// Извлекаем SNI из plugin если есть
	if strings.Contains(link, "plugin=") {
		pluginMatch := regexp.MustCompile(`plugin=([^&]+)`).FindStringSubmatch(link)
		if len(pluginMatch) > 1 {
			pluginArgs, _ := url.QueryUnescape(pluginMatch[1])
			hostMatch := regexp.MustCompile(`host=([^;&]+)`).FindStringSubmatch(pluginArgs)
			if len(hostMatch) > 1 {
				node.Config["sni"] = hostMatch[1]
			}
		}
	}

	return node, nil
}

func parseHysteria2(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "hysteria2", Config: make(map[string]interface{})}

	link = strings.TrimPrefix(link, "hysteria2://")
	link = strings.TrimPrefix(link, "hy2://")

	mainPart := link
	if idx := strings.Index(link, "#"); idx != -1 {
		mainPart = link[:idx]
		node.Name, _ = url.QueryUnescape(link[idx+1:])
	}

	// hysteria2://auth@host:port?sni=xxx
	re := regexp.MustCompile(`([^@]+)@([^:]+):(\d+)(?:\?(.+))?$`)
	matches := re.FindStringSubmatch(mainPart)
	if len(matches) < 4 {
		return nil, fmt.Errorf("invalid hysteria2 link")
	}

	node.Config["auth"] = matches[1]
	node.Address = matches[2]
	node.Port, _ = strconv.Atoi(matches[3])

	if len(matches) > 4 && matches[4] != "" {
		params := parseQueryParams(matches[4])
		node.Config["sni"] = params.Get("sni")
	}

	return node, nil
}

func parseTUIC(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "tuic", Config: make(map[string]interface{})}

	link = strings.TrimPrefix(link, "tuic://")

	mainPart := link
	if idx := strings.Index(link, "#"); idx != -1 {
		mainPart = link[:idx]
		node.Name, _ = url.QueryUnescape(link[idx+1:])
	}

	// tuic://uuid:password@host:port?sni=xxx
	re := regexp.MustCompile(`([^:]+):([^@]+)@([^:]+):(\d+)(?:\?(.+))?$`)
	matches := re.FindStringSubmatch(mainPart)
	if len(matches) < 5 {
		return nil, fmt.Errorf("invalid tuic link")
	}

	node.Config["uuid"] = matches[1]
	node.Config["password"] = matches[2]
	node.Address = matches[3]
	node.Port, _ = strconv.Atoi(matches[4])

	if len(matches) > 5 && matches[5] != "" {
		params := parseQueryParams(matches[5])
		node.Config["sni"] = params.Get("sni")
	}

	return node, nil
}

func parseQueryParams(query string) url.Values {
	values, _ := url.ParseQuery(query)
	return values
}

func processNodes(nodes []*ProxyNode) []CheckResult {
	var wg sync.WaitGroup
	nodeChan := make(chan *ProxyNode, len(nodes))
	resultChan := make(chan CheckResult, len(nodes))

	for i := 0; i < WorkerCount; i++ {
		wg.Add(1)
		go worker(&wg, nodeChan, resultChan)
	}

	for _, node := range nodes {
		nodeChan <- node
	}
	close(nodeChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []CheckResult
	processed := 0
	for result := range resultChan {
		processed++
		if processed%100 == 0 {
			fmt.Printf("⏳ Processed: %d/%d | Success: %d\n", processed, len(nodes), len(results))
		}
		if result.Success {
			results = append(results, result)
		}
	}
	return results
}

func worker(wg *sync.WaitGroup, nodeChan <-chan *ProxyNode, resultChan chan<- CheckResult) {
	defer wg.Done()
	for node := range nodeChan {
		result := checkNode(node)
		resultChan <- result
	}
}

func checkNode(node *ProxyNode) CheckResult {
	result := CheckResult{Node: node, Success: false}

	// === 1. ПРОВЕРКА SNI ===
	nodeSNI := getConfigValue(node.Config, "sni", "")

	// SNI обязателен для всех кроме SS
	if node.Protocol != "shadowsocks" && nodeSNI == "" {
		atomic.AddInt32(&statsNoSNI, 1)
		return result
	}

	// === 2. ПРОВЕРКА TLD ===
	if nodeSNI != "" && isBannedTLD(nodeSNI) {
		atomic.AddInt32(&statsBannedTLD, 1)
		return result
	}

	// === 3. ПРОВЕРКА ЗАПРЕЩЁННЫХ ПАТТЕРНОВ ===
	if nodeSNI != "" && hasBannedPattern(nodeSNI) {
		atomic.AddInt32(&statsBannedPattern, 1)
		return result
	}

	// === 4. ПРОВЕРКА ПОРТА ===
	if !isValidPort(node.Protocol, node.Port) {
		atomic.AddInt32(&statsInvalidPort, 1)
		return result
	}

	// === 5. ПРОВЕРКА WHITELIST SNI ===
	if len(sniWhitelist) > 0 && nodeSNI != "" {
		if !isTargetSNI(nodeSNI, sniWhitelist) {
			atomic.AddInt32(&statsSNIRejected, 1)
			return result
		}
	}

	// === 6. ПРОВЕРКА СТРАНЫ ===
	countryID := getCountryCode(node.Address)
	if BannedCountries[countryID] {
		atomic.AddInt32(&statsBannedCountry, 1)
		return result
	}

	// === 7. ЗАПУСК ПРОВЕРКИ ===
	port := int(atomic.AddInt32(&portCounter, 1))
	if port > MaxPortRange {
		atomic.StoreInt32(&portCounter, MinPortRange)
		port = MinPortRange
	}

	configPath := fmt.Sprintf("cfg_%d.json", port)
	defer os.Remove(configPath)

	var err error
	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Выбираем движок по протоколу
	if node.Protocol == "hysteria2" || node.Protocol == "tuic" {
		err = generateSingBoxConfig(node, port, configPath)
		if err != nil {
			atomic.AddInt32(&statsConfigFailed, 1)
			return result
		}
		cmd = exec.CommandContext(ctx, "./sing-box", "run", "-c", configPath)
	} else {
		err = generateXrayConfig(node, port, configPath)
		if err != nil {
			atomic.AddInt32(&statsConfigFailed, 1)
			return result
		}
		cmd = exec.CommandContext(ctx, "./xray", "run", "-c", configPath)
	}

	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		atomic.AddInt32(&statsConfigFailed, 1)
		return result
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	// Ждём порт
	portReady := false
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			portReady = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !portReady {
		atomic.AddInt32(&statsConnectFailed, 1)
		return result
	}

	// Проверка соединения
	testURL := randomTestURL()
	if !checkConnectivity(port, testURL) {
		testURL2 := randomTestURL()
		if !checkConnectivity(port, testURL2) {
			atomic.AddInt32(&statsConnectFailed, 1)
			return result
		}
	}

	// Замер скорости
	speed := measureSpeed(port)
	if speed < 1.0 {
		atomic.AddInt32(&statsSpeedFailed, 1)
		return result
	}

	atomic.AddInt32(&statsSuccess, 1)
	result.Speed = speed
	result.CountryID = countryID
	result.Success = true
	return result
}

func generateXrayConfig(node *ProxyNode, port int, filename string) error {
	config := XrayConfig{
		Log: map[string]interface{}{"loglevel": "none"},
		Inbounds: []map[string]interface{}{
			{
				"port":     port,
				"protocol": "socks",
				"settings": map[string]interface{}{"udp": true},
			},
		},
	}

	var outbound map[string]interface{}

	switch node.Protocol {
	case "vless":
		outbound = map[string]interface{}{
			"protocol": "vless",
			"settings": map[string]interface{}{
				"vnext": []map[string]interface{}{
					{
						"address": node.Address,
						"port":    node.Port,
						"users": []map[string]interface{}{
							{
								"id":         node.Config["uuid"],
								"encryption": getConfigValue(node.Config, "encryption", "none"),
								"flow":       node.Config["flow"],
							},
						},
					},
				},
			},
			"streamSettings": buildStreamSettings(node),
		}
	case "trojan":
		outbound = map[string]interface{}{
			"protocol": "trojan",
			"settings": map[string]interface{}{
				"servers": []map[string]interface{}{
					{
						"address":  node.Address,
						"port":     node.Port,
						"password": node.Config["password"],
					},
				},
			},
			"streamSettings": buildStreamSettings(node),
		}
	case "shadowsocks":
		outbound = map[string]interface{}{
			"protocol": "shadowsocks",
			"settings": map[string]interface{}{
				"servers": []map[string]interface{}{
					{
						"address":  node.Address,
						"port":     node.Port,
						"method":   node.Config["method"],
						"password": node.Config["password"],
					},
				},
			},
		}
	}

	config.Outbounds = []map[string]interface{}{outbound}
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(filename, data, 0644)
}

func generateSingBoxConfig(node *ProxyNode, port int, filename string) error {
	config := SingBoxConfig{
		Log: map[string]interface{}{"level": "warn"},
		Inbounds: []map[string]interface{}{
			{
				"type": "socks",
				"tag":  "socks-in",
				"listen": "127.0.0.1",
				"listen_port": port,
			},
		},
	}

	var outbound map[string]interface{}

	switch node.Protocol {
	case "hysteria2":
		outbound = map[string]interface{}{
			"type": "hysteria2",
			"tag":  "proxy",
			"server": node.Address,
			"server_port": node.Port,
			"password": node.Config["auth"],
			"tls": map[string]interface{}{
				"enabled":           true,
				"server_name":       node.Config["sni"],
				"insecure":          true,
			},
		}
	case "tuic":
		outbound = map[string]interface{}{
			"type": "tuic",
			"tag":  "proxy",
			"server": node.Address,
			"server_port": node.Port,
			"uuid": node.Config["uuid"],
			"password": node.Config["password"],
			"tls": map[string]interface{}{
				"enabled":           true,
				"server_name":       node.Config["sni"],
				"insecure":          true,
			},
		}
	}

	config.Outbounds = []map[string]interface{}{outbound}
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(filename, data, 0644)
}

func buildStreamSettings(node *ProxyNode) map[string]interface{} {
	netType := getConfigValue(node.Config, "type", "tcp")
	if idx := strings.IndexAny(netType, "#&; "); idx != -1 {
		netType = netType[:idx]
	}
	if netType == "" {
		netType = "tcp"
	}

	streamSettings := map[string]interface{}{"network": netType}
	security := getConfigValue(node.Config, "security", "none")
	flow := getConfigValue(node.Config, "flow", "")

	if flow == "xtls-rprx-vision" && security == "none" {
		security = "tls"
	}

	fp := getConfigValue(node.Config, "fp", "chrome")

	if security == "tls" {
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName":    node.Config["sni"],
			"fingerprint":   fp,
			"alpn":          []string{"h2", "http/1.1"},
			"allowInsecure": true,
		}
	} else if security == "reality" {
		streamSettings["security"] = "reality"
		streamSettings["realitySettings"] = map[string]interface{}{
			"serverName":  node.Config["sni"],
			"publicKey":   node.Config["pbk"],
			"shortId":     node.Config["sid"],
			"fingerprint": fp,
			"spiderX":     "/",
		}
	}
	return streamSettings
}

func getConfigValue(config map[string]interface{}, key, defaultVal string) string {
	if val, ok := config[key]; ok && val != nil {
		if strVal, ok := val.(string); ok && strVal != "" {
			return strVal
		}
	}
	return defaultVal
}

func checkConnectivity(port int, testURL string) bool {
	dialer, err := goproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, goproxy.Direct)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial:              dialer.Dial,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		Timeout: TimeoutCheck,
	}

	resp, err := client.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 400
}

func measureSpeed(port int) float64 {
	dialer, err := goproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, goproxy.Direct)
	if err != nil {
		return 0
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial:              dialer.Dial,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		Timeout: TimeoutSpeed,
	}

	start := time.Now()
	resp, err := client.Get(SpeedTestURL)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	buf := make([]byte, 32768)
	downloaded := int64(0)
	for downloaded < SpeedTestSize {
		n, err := resp.Body.Read(buf)
		downloaded += int64(n)
		if err != nil {
			break
		}
		if time.Since(start) > TimeoutSpeed {
			break
		}
	}

	duration := time.Since(start).Seconds()
	if duration == 0 {
		return 0
	}
	return (float64(downloaded) * 8) / (duration * 1024 * 1024)
}

func getCountryCode(address string) string {
	ips, err := net.LookupIP(address)
	if err != nil || len(ips) == 0 {
		ip := net.ParseIP(address)
		if ip != nil {
			ips = []net.IP{ip}
		} else {
			return "UN"
		}
	}

	record, err := geoIPReader.Country(ips[0])
	if err != nil {
		return "UN"
	}
	return record.Country.IsoCode
}

func saveResults(results []CheckResult) {
	ufFile, _ := os.Create("uf.txt")
	fastFile, _ := os.Create("fast.txt")
	normFile, _ := os.Create("norm.txt")
	hy2File, _ := os.Create("hy2.txt")
	tuicFile, _ := os.Create("tuic.txt")

	defer ufFile.Close()
	defer fastFile.Close()
	defer normFile.Close()
	defer hy2File.Close()
	defer tuicFile.Close()

	for _, result := range results {
		flag := countryFlags[result.CountryID]
		if flag == "" {
			flag = "🌐"
		}
		country := result.CountryID
		if country == "" {
			country = "UN"
		}

		protocol := strings.ToUpper(result.Node.Protocol)
		speedStr := fmt.Sprintf("%.1f MB/s", result.Speed)

		var speedTag string
		var file *os.File
		if result.Speed >= UltraFastSpeed {
			speedTag = "UF"
			file = ufFile
		} else if result.Speed >= FastSpeed {
			speedTag = "FAST"
			file = fastFile
		} else {
			speedTag = "NORM"
			file = normFile
		}

		name := fmt.Sprintf("#[%s] %s %s | %s | %s", protocol, flag, country, speedStr, speedTag)
		link := strings.Split(result.Node.RawLink, "#")[0]
		newLink := fmt.Sprintf("%s#%s\n", link, url.QueryEscape(name))
		file.WriteString(newLink)

		// Отдельные файлы для hy2/tuic
		if result.Node.Protocol == "hysteria2" {
			hy2File.WriteString(newLink)
		} else if result.Node.Protocol == "tuic" {
			tuicFile.WriteString(newLink)
		}
	}

	fmt.Printf("\n📊 Results:\n")
	fmt.Printf("   💎 Ultra Fast: %d\n", countLinesInFile("uf.txt"))
	fmt.Printf("   ⚡ Fast:       %d\n", countLinesInFile("fast.txt"))
	fmt.Printf("   ✅ Normal:     %d\n", countLinesInFile("norm.txt"))
	fmt.Printf("   🚀 Hysteria2:  %d\n", countLinesInFile("hy2.txt"))
	fmt.Printf("   🔷 TUIC:       %d\n", countLinesInFile("tuic.txt"))
}

func countLinesInFile(filename string) int {
	file, err := os.Open(filename)
	if err != nil {
		return 0
	}
	defer file.Close()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count
}
