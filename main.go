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
	WorkerCount    = 120
	MinPortRange   = 20000
	MaxPortRange   = 35000
	XrayURL        = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
	GeoIPURL       = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
	SpeedTestURL   = "https://speed.cloudflare.com/__down?bytes=2097152"
	SpeedTestSize  = 1 * 1024 * 1024
	TimeoutCheck   = 12 * time.Second
	TimeoutSpeed   = 18 * time.Second
	UltraFastSpeed = 3.5
	FastSpeed      = 2.5
)

// === ТЕСТОВЫЕ URL ДЛЯ РОТАЦИИ ===
var testURLs = []string{
	"https://www.youtube.com/generate_204",
	"https://play.google.com/log?format=json&hasfast=true",
	"https://www.google.com/generate_204",
	"https://clients4.google.com/generate_204",
	"https://www.gstatic.com/generate_204",
}

// === FINGERPRINTS ДЛЯ РАНДОМИЗАЦИИ ===
var fingerprints = []string{
	"chrome",
	"firefox", 
	"safari",
	"edge",
	"ios",
	"android",
	"random",
	"randomized",
}

// === ПУТИ ДЛЯ SPIDERX (РЕАЛИСТИЧНЫЕ) ===
var spiderXPaths = []string{
	"/",
	"/index.html",
	"/home",
	"/api/v1",
	"/static/main.js",
	"/assets/bundle.css",
	"/images/logo.png",
	"/fonts/roboto.woff2",
	"/manifest.json",
	"/sw.js",
	"/favicon.ico",
	"/robots.txt",
	"/sitemap.xml",
}

var (
	countryFlags = map[string]string{
		"US": "🇺🇸", "GB": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "NL": "🇳🇱",
		"CA": "🇨🇦", "JP": "🇯🇵", "KR": "🇰🇷", "SG": "🇸🇬", "HK": "🇭🇰",
		"TW": "🇹🇼", "AU": "🇦🇺", "RU": "🇷🇺", "CN": "🇨🇳", "IN": "🇮🇳",
		"BR": "🇧🇷", "TR": "🇹🇷", "SE": "🇸🇪", "PL": "🇵🇱", "IT": "🇮🇹",
		"ES": "🇪🇸", "CH": "🇨🇭", "FI": "🇫🇮", "NO": "🇳🇴", "DK": "🇩🇰",
	}

	// Счётчики
	statsTotalInput    int32
	statsParseFailed   int32
	statsNoSNI         int32
	statsSNIRejected   int32
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

var geoIPReader *geoip2.Reader
var portCounter int32 = MinPortRange

// === РАНДОМИЗАЦИЯ ===

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

func randomDelay(minMs, maxMs int) time.Duration {
	delay := minMs + rand.Intn(maxMs-minMs)
	return time.Duration(delay) * time.Millisecond
}

// === ОСНОВНОЙ КОД ===

func main() {
	fmt.Println("🚀 Starting L7 Proxy Checker (Stealth Edition)")
	fmt.Println("==============================================")

	inputFile := flag.String("input", "proxies.txt", "Path to the input proxy list file")
	whitelistFile := flag.String("whitelist", "whitelist.txt", "Path to the SNI whitelist file")
	flag.Parse()

	if err := setupDependencies(); err != nil {
		fmt.Printf("❌ Failed to setup dependencies: %v\n", err)
		os.Exit(1)
	}

	var err error
	geoIPReader, err = geoip2.Open("GeoLite2-Country.mmdb")
	if err != nil {
		fmt.Printf("❌ Failed to open GeoIP database: %v\n", err)
		os.Exit(1)
	}
	defer geoIPReader.Close()

	sniWhitelist, err := readSNIWhitelist(*whitelistFile)
	if err != nil {
		fmt.Printf("⚠️ Could not read SNI whitelist, continuing without SNI checks: %v\n", err)
		sniWhitelist = []string{}
	} else {
		fmt.Printf("📋 Loaded %d SNI domains in whitelist\n", len(sniWhitelist))
	}

	// Подсчёт строк
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
	fmt.Printf("📋 Parsed successfully: %d nodes\n", len(nodes))
	fmt.Printf("❌ Parse failures: %d\n", statsParseFailed)

	results := processNodes(nodes, sniWhitelist)
	saveResults(results)

	// Статистика
	fmt.Println("\n==============================================")
	fmt.Println("📊 FINAL STATISTICS:")
	fmt.Printf("   📥 Input lines:     %d\n", statsTotalInput)
	fmt.Printf("   ❌ Parse failed:    %d (%.1f%%)\n", statsParseFailed, float64(statsParseFailed)*100/float64(statsTotalInput))
	fmt.Printf("   🚫 No SNI:          %d\n", statsNoSNI)
	fmt.Printf("   🔒 SNI rejected:    %d\n", statsSNIRejected)
	fmt.Printf("   ⚙️ Config failed:    %d\n", statsConfigFailed)
	fmt.Printf("   🔌 Connect failed:  %d\n", statsConnectFailed)
	fmt.Printf("   🐌 Speed too low:   %d\n", statsSpeedFailed)
	fmt.Printf("   ✅ Success:         %d\n", statsSuccess)
	fmt.Println("==============================================")
}

func setupDependencies() error {
	if _, err := os.Stat("xray"); os.IsNotExist(err) {
		fmt.Println("📥 Downloading Xray Core...")
		if err := downloadFile("xray.zip", XrayURL); err != nil {
			return err
		}
		if err := exec.Command("unzip", "-o", "xray.zip", "xray").Run(); err != nil {
			return err
		}
		os.Chmod("xray", 0755)
		os.Remove("xray.zip")
	}
	if _, err := os.Stat("GeoLite2-Country.mmdb"); os.IsNotExist(err) {
		fmt.Println("📥 Downloading GeoIP database...")
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
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sni := strings.TrimSpace(line)
		sni = strings.TrimPrefix(sni, ".")
		if sni != "" {
			snis = append(snis, sni)
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
	if strings.HasPrefix(link, "vless://") {
		return parseVLESS(link)
	} else if strings.HasPrefix(link, "trojan://") {
		return parseTrojan(link)
	} else if strings.HasPrefix(link, "ss://") {
		return parseShadowsocks(link)
	}
	return nil, fmt.Errorf("unsupported protocol")
}

func parseVLESS(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "vless", Config: make(map[string]interface{})}

	// Исправленная регулярка с опциональным слешем
	re := regexp.MustCompile(`vless://([^@]+)@([^:]+):(\d+)/?\?(.+)`)
	matches := re.FindStringSubmatch(link)
	if len(matches) < 5 {
		return nil, fmt.Errorf("invalid vless link")
	}
	uuid := matches[1]
	node.Address = matches[2]
	node.Port, _ = strconv.Atoi(matches[3])
	params := parseQueryParams(matches[4])

	node.Config["uuid"] = uuid
	node.Config["security"] = params.Get("security")
	node.Config["encryption"] = params.Get("encryption")
	node.Config["flow"] = params.Get("flow")
	node.Config["type"] = params.Get("type")
	node.Config["sni"] = params.Get("sni")
	node.Config["fp"] = params.Get("fp")
	node.Config["pbk"] = params.Get("pbk")
	node.Config["sid"] = params.Get("sid")
	node.Name = params.Get("fragment")
	if node.Name == "" {
		parts := strings.Split(link, "#")
		if len(parts) > 1 {
			node.Name, _ = url.QueryUnescape(parts[1])
		}
	}
	return node, nil
}

func parseTrojan(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "trojan", Config: make(map[string]interface{})}

	re := regexp.MustCompile(`trojan://([^@]+)@([^:]+):(\d+)/?\?(.+)`)
	matches := re.FindStringSubmatch(link)
	if len(matches) < 5 {
		return nil, fmt.Errorf("invalid trojan link")
	}
	node.Config["password"] = matches[1]
	node.Address = matches[2]
	node.Port, _ = strconv.Atoi(matches[3])
	params := parseQueryParams(matches[4])

	node.Config["sni"] = params.Get("sni")
	node.Config["type"] = params.Get("type")
	node.Config["security"] = params.Get("security")
	node.Name = params.Get("fragment")
	if node.Name == "" {
		parts := strings.Split(link, "#")
		if len(parts) > 1 {
			node.Name, _ = url.QueryUnescape(parts[1])
		}
	}
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

	serverPart := atParts[1]
	serverPort := strings.Split(serverPart, ":")
	if len(serverPort) < 2 {
		return nil, fmt.Errorf("invalid shadowsocks server:port")
	}
	node.Address = serverPort[0]
	node.Port, _ = strconv.Atoi(serverPort[1])
	return node, nil
}

func parseQueryParams(query string) url.Values {
	values, _ := url.ParseQuery(query)
	return values
}

func processNodes(nodes []*ProxyNode, sniWhitelist []string) []CheckResult {
	var wg sync.WaitGroup
	nodeChan := make(chan *ProxyNode, len(nodes))
	resultChan := make(chan CheckResult, len(nodes))

	for i := 0; i < WorkerCount; i++ {
		wg.Add(1)
		go worker(&wg, nodeChan, resultChan, sniWhitelist)
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

func worker(wg *sync.WaitGroup, nodeChan <-chan *ProxyNode, resultChan chan<- CheckResult, sniWhitelist []string) {
	defer wg.Done()
	for node := range nodeChan {
		result := checkNode(node, sniWhitelist)
		resultChan <- result
	}
}

func checkNode(node *ProxyNode, sniWhitelist []string) CheckResult {
	result := CheckResult{Node: node, Success: false}

	// Фильтрация SNI
	if len(sniWhitelist) > 0 {
		nodeSNI := getConfigValue(node.Config, "sni", "")
		if nodeSNI == "" {
			atomic.AddInt32(&statsNoSNI, 1)
			return result
		}
		if !isTargetSNI(nodeSNI, sniWhitelist) {
			atomic.AddInt32(&statsSNIRejected, 1)
			return result
		}
	}

	port := int(atomic.AddInt32(&portCounter, 1))
	if port > MaxPortRange {
		atomic.StoreInt32(&portCounter, MinPortRange)
		port = MinPortRange
	}

	configPath := fmt.Sprintf("cfg_%d.json", port)
	defer os.Remove(configPath)

	if err := generateXrayConfig(node, port, configPath); err != nil {
		atomic.AddInt32(&statsConfigFailed, 1)
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./xray", "run", "-c", configPath)
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

	// === РАНДОМИЗИРОВАННАЯ ЗАДЕРЖКА ===
	time.Sleep(randomDelay(300, 800))

	// === РОТАЦИЯ ТЕСТОВОГО URL ===
	testURL := randomTestURL()
	if !checkConnectivity(port, testURL) {
		// Вторая попытка с другим URL
		testURL2 := randomTestURL()
		if !checkConnectivity(port, testURL2) {
			atomic.AddInt32(&statsConnectFailed, 1)
			return result
		}
	}

	speed := measureSpeed(port)
	if speed < 1.0 {
		atomic.AddInt32(&statsSpeedFailed, 1)
		return result
	}

	atomic.AddInt32(&statsSuccess, 1)
	countryID := getCountryCode(node.Address)
	result.Speed = speed
	result.CountryID = countryID
	result.Success = true
	return result
}

func generateXrayConfig(node *ProxyNode, port int, filename string) error {
	config := XrayConfig{
		Log: map[string]interface{}{
			"loglevel": "none",
		},
		Inbounds: []map[string]interface{}{
			{
				"port":     port,
				"protocol": "socks",
				"settings": map[string]interface{}{
					"udp": true,
				},
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
	default:
		return fmt.Errorf("unsupported protocol: %s", node.Protocol)
	}

	config.Outbounds = []map[string]interface{}{outbound}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func buildStreamSettings(node *ProxyNode) map[string]interface{} {
	streamSettings := map[string]interface{}{
		"network": getConfigValue(node.Config, "type", "tcp"),
	}

	security := getConfigValue(node.Config, "security", "none")
	flow := getConfigValue(node.Config, "flow", "")

	if flow == "xtls-rprx-vision" && security == "none" {
		security = "tls"
	}

	// === РАНДОМИЗАЦИЯ FINGERPRINT ===
	fp := randomFingerprint()

	if security == "tls" {
		streamSettings["security"] = "tls"
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName":    node.Config["sni"],
			"fingerprint":   fp, // Рандомизированный
			"alpn":          []string{"h2", "http/1.1"},
			"allowInsecure": true,
		}
	} else if security == "reality" {
		streamSettings["security"] = "reality"
		streamSettings["realitySettings"] = map[string]interface{}{
			"serverName":  node.Config["sni"],
			"publicKey":   node.Config["pbk"],
			"shortId":     node.Config["sid"],
			"fingerprint": fp,              // Рандомизированный
			"spiderX":     randomSpiderX(), // Рандомизированный путь
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

func isTargetSNI(nodeSNI string, whitelist []string) bool {
	if nodeSNI == "" {
		return false
	}
	for _, suffix := range whitelist {
		if strings.HasSuffix(nodeSNI, "."+suffix) || nodeSNI == suffix {
			return true
		}
	}
	return false
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
			MaxIdleConns:      1,
		},
		Timeout: TimeoutCheck,
	}

	resp, err := client.Get(testURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 204 || resp.StatusCode == 200
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
			MaxIdleConns:      1,
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
	mbps := (float64(downloaded) * 8) / (duration * 1024 * 1024)
	return mbps
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

	defer ufFile.Close()
	defer fastFile.Close()
	defer normFile.Close()

	for _, result := range results {
		flag := countryFlags[result.CountryID]
		if flag == "" {
			flag = "🌐"
		}
		name := result.Node.Name
		name = strings.ReplaceAll(name, "🌐 UN", fmt.Sprintf("%s %s", flag, result.CountryID))

		var speedTag string
		var file *os.File
		if result.Speed >= UltraFastSpeed {
			speedTag = " | YT | UF"
			file = ufFile
		} else if result.Speed >= FastSpeed {
			speedTag = " | YT | FAST"
			file = fastFile
		} else {
			speedTag = " | YT | NORM"
			file = normFile
		}
		link := strings.Split(result.Node.RawLink, "#")[0]
		newLink := fmt.Sprintf("%s#%s%s\n", link, url.QueryEscape(name), speedTag)
		file.WriteString(newLink)
	}

	fmt.Printf("\n📊 Results saved:\n")
	fmt.Printf("   💎 Ultra Fast: %d\n", countLinesInFile("uf.txt"))
	fmt.Printf("   ⚡ Fast:       %d\n", countLinesInFile("fast.txt"))
	fmt.Printf("   ✅ Normal:     %d\n", countLinesInFile("norm.txt"))
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
 
