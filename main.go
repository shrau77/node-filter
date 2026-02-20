package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
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

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

const (
	WorkerCount    = 80
	MinPortRange   = 20000
	MaxPortRange   = 35000
	XrayURL        = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
	GeoIPURL       = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
	TimeoutCheck   = 10 * time.Second
	TimeoutSpeed   = 15 * time.Second
	UltraFastSpeed = 3.5
	FastSpeed      = 2.5
	SpeedTestSize  = 1 * 1024 * 1024
)

// Множественные speed test URL (как в a2ray.py)
var speedTestURLs = []string{
	"https://speed.cloudflare.com/__down?bytes=10000000",
	"https://proof.ovh.net/files/10Mb.dat",
	"https://speed.hetzner.de/10MB.bin",
}

// Тестовые URL для проверки связности
var testURLs = []string{
	"http://gstatic.com/generate_204",
	"http://cp.cloudflare.com/generate_204",
}

// Regex для валидации Reality (как в a2ray.py)
var (
	RealityPBKRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{43,44}$`)
	RealitySIDRegex = regexp.MustCompile(`^[0-9a-fA-F]{0,32}$`)
)

// ============================================================================
// СТРУКТУРЫ
// ============================================================================

type ProxyNode struct {
	RawLink  string
	Protocol string
	Address  string
	Port     int
	Name     string
	Config   map[string]string
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

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================

var (
	geoIPReader *geoip2.Reader
	portCounter int32 = MinPortRange

	// Статистика
	statsTotal       int32
	statsParseFail   int32
	statsNoSNI       int32
	statsSNIFail     int32
	statsConfigFail  int32
	statsConnectFail int32
	statsSpeedFail   int32
	statsSuccess     int32

	countryFlags = map[string]string{
		"US": "🇺🇸", "GB": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "NL": "🇳🇱",
		"CA": "🇨🇦", "JP": "🇯🇵", "KR": "🇰🇷", "SG": "🇸🇬", "HK": "🇭🇰",
		"TW": "🇹🇼", "AU": "🇦🇺", "RU": "🇷🇺", "CN": "🇨🇳", "IN": "🇮🇳",
		"BR": "🇧🇷", "TR": "🇹🇷", "SE": "🇸🇪", "PL": "🇵🇱", "IT": "🇮🇹",
		"ES": "🇪🇸", "CH": "🇨🇭", "FI": "🇫🇮", "NO": "🇳🇴", "DK": "🇩🇰",
	}
)

// ============================================================================
// ПАРСИНГ (проверенный подход с исправленной регуляркой)
// ============================================================================

func parseProxyLink(link string) (*ProxyNode, error) {
	link = strings.TrimSpace(link)
	link = strings.TrimPrefix(link, "\ufeff")
	link = strings.TrimPrefix(link, "\u200b")

	if strings.HasPrefix(link, "vless://") {
		return parseVLESS(link)
	} else if strings.HasPrefix(link, "trojan://") {
		return parseTrojan(link)
	} else if strings.HasPrefix(link, "ss://") {
		return parseShadowsocks(link)
	} else if strings.HasPrefix(link, "vmess://") {
		return parseVMess(link)
	}
	return nil, fmt.Errorf("unsupported protocol")
}

func parseVLESS(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "vless", Config: make(map[string]string)}

	// Отделяем имя
	mainPart := link
	if idx := strings.Index(link, "#"); idx != -1 {
		mainPart = link[:idx]
		node.Name, _ = url.QueryUnescape(link[idx+1:])
	}

	// Исправленная регулярка - опциональный слеш перед ?
	re := regexp.MustCompile(`vless://([^@]+)@([^:]+):(\d+)/?\?(.+)`)
	matches := re.FindStringSubmatch(mainPart)
	if len(matches) < 5 {
		return nil, fmt.Errorf("invalid vless format")
	}

	node.Config["uuid"] = matches[1]
	node.Address = matches[2]
	node.Port, _ = strconv.Atoi(matches[3])

	// Парсим query
	params, _ := url.ParseQuery(matches[4])
	node.Config["security"] = getParam(params, "security", "none")
	node.Config["encryption"] = getParam(params, "encryption", "none")
	node.Config["type"] = getParam(params, "type", "tcp")
	node.Config["sni"] = getParam(params, "sni", "")
	node.Config["fp"] = getParam(params, "fp", "chrome")
	node.Config["flow"] = getParam(params, "flow", "")
	node.Config["path"] = getParam(params, "path", "")
	node.Config["host"] = getParam(params, "host", "")
	node.Config["serviceName"] = getParam(params, "serviceName", "")
	node.Config["alpn"] = getParam(params, "alpn", "")

	// Reality параметры
	pbk := getParam(params, "pbk", "")
	sid := getParam(params, "sid", "")

	// Валидация Reality
	if node.Config["security"] == "reality" {
		if pbk != "" && !RealityPBKRegex.MatchString(pbk) {
			pbk = "" // Невалидный
		}
		if sid != "" && !RealitySIDRegex.MatchString(sid) {
			sid = ""
		}
	}
	node.Config["pbk"] = pbk
	node.Config["sid"] = sid

	// Автоисправление security
	if pbk != "" && node.Config["security"] == "none" {
		node.Config["security"] = "reality"
	}

	return node, nil
}

func parseTrojan(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "trojan", Config: make(map[string]string)}

	mainPart := link
	if idx := strings.Index(link, "#"); idx != -1 {
		mainPart = link[:idx]
		node.Name, _ = url.QueryUnescape(link[idx+1:])
	}

	re := regexp.MustCompile(`trojan://([^@]+)@([^:]+):(\d+)/?\?(.+)`)
	matches := re.FindStringSubmatch(mainPart)
	if len(matches) < 5 {
		return nil, fmt.Errorf("invalid trojan format")
	}

	node.Config["password"] = matches[1]
	node.Address = matches[2]
	node.Port, _ = strconv.Atoi(matches[3])

	params, _ := url.ParseQuery(matches[4])
	node.Config["security"] = getParam(params, "security", "tls")
	node.Config["sni"] = getParam(params, "sni", "")
	node.Config["type"] = getParam(params, "type", "tcp")
	node.Config["fp"] = getParam(params, "fp", "chrome")

	return node, nil
}

func parseShadowsocks(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "shadowsocks", Config: make(map[string]string)}

	link = strings.TrimPrefix(link, "ss://")

	mainPart := link
	if idx := strings.Index(link, "#"); idx != -1 {
		mainPart = link[:idx]
		node.Name, _ = url.QueryUnescape(link[idx+1:])
	}

	// Формат: base64(method:pass)@host:port или method:pass@host:port
	if idx := strings.Index(mainPart, "@"); idx != -1 {
		userInfo := mainPart[:idx]
		serverPart := mainPart[idx+1:]

		// Декодируем userInfo
		var decoded string
		if b, err := base64.StdEncoding.DecodeString(userInfo + "=="); err == nil {
			decoded = string(b)
		} else if b, err := base64.RawURLEncoding.DecodeString(userInfo); err == nil {
			decoded = string(b)
		} else {
			decoded = userInfo
		}

		if idx := strings.Index(decoded, ":"); idx != -1 {
			node.Config["method"] = decoded[:idx]
			node.Config["password"] = decoded[idx+1:]
		}

		// Парсим сервер
		hostPort := strings.Split(serverPart, ":")
		if len(hostPort) >= 2 {
			node.Address = hostPort[0]
			node.Port, _ = strconv.Atoi(hostPort[1])
		}
	}

	if node.Address == "" || node.Port == 0 {
		return nil, fmt.Errorf("invalid ss link")
	}

	return node, nil
}

func parseVMess(link string) (*ProxyNode, error) {
	node := &ProxyNode{RawLink: link, Protocol: "vmess", Config: make(map[string]string)}

	link = strings.TrimPrefix(link, "vmess://")

	mainPart := link
	if idx := strings.Index(link, "#"); idx != -1 {
		mainPart = link[:idx]
		node.Name, _ = url.QueryUnescape(link[idx+1:])
	}

	// Base64 декодирование
	var decoded string
	if b, err := base64.StdEncoding.DecodeString(mainPart + "=="); err == nil {
		decoded = string(b)
	} else if b, err := base64.RawURLEncoding.DecodeString(mainPart); err == nil {
		decoded = string(b)
	} else {
		return nil, fmt.Errorf("invalid base64")
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &data); err != nil {
		return nil, err
	}

	node.Config["uuid"] = getString(data, "id")
	node.Address = getString(data, "add")
	node.Port = getInt(data, "port")
	node.Config["aid"] = strconv.Itoa(getInt(data, "aid"))
	node.Config["security"] = getString(data, "tls")
	if node.Config["security"] == "" {
		node.Config["security"] = "none"
	}
	node.Config["type"] = getString(data, "net")
	if node.Config["type"] == "" {
		node.Config["type"] = "tcp"
	}
	node.Config["path"] = getString(data, "path")
	node.Config["host"] = getString(data, "host")
	node.Config["sni"] = getString(data, "sni")
	if node.Name == "" {
		node.Name = getString(data, "ps")
	}

	if node.Address == "" || node.Port == 0 {
		return nil, fmt.Errorf("missing host/port")
	}

	return node, nil
}

func getParam(params url.Values, key, def string) string {
	if v := params.Get(key); v != "" {
		return v
	}
	return def
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		case string:
			i, _ := strconv.Atoi(n)
			return i
		}
	}
	return 0
}

// ============================================================================
// ГЕНЕРАЦИЯ КОНФИГА XRAY
// ============================================================================

func generateXrayConfig(node *ProxyNode, port int) (string, error) {
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

	outbound, err := createOutbound(node)
	if err != nil {
		return "", err
	}
	config.Outbounds = []map[string]interface{}{outbound}

	data, _ := json.MarshalIndent(config, "", "  ")
	configPath := fmt.Sprintf("cfg_%d.json", port)
	os.WriteFile(configPath, data, 0644)
	return configPath, nil
}

func createOutbound(node *ProxyNode) (map[string]interface{}, error) {
	outbound := map[string]interface{}{"protocol": node.Protocol}

	switch node.Protocol {
	case "vless":
		user := map[string]interface{}{
			"id":         node.Config["uuid"],
			"encryption": node.Config["encryption"],
		}
		if node.Config["flow"] != "" {
			user["flow"] = node.Config["flow"]
		}

		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": node.Address,
					"port":    node.Port,
					"users":   []map[string]interface{}{user},
				},
			},
		}
		outbound["streamSettings"] = buildStreamSettings(node)

	case "vmess":
		aid := 0
		if node.Config["aid"] != "" {
			aid, _ = strconv.Atoi(node.Config["aid"])
		}
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": node.Address,
					"port":    node.Port,
					"users": []map[string]interface{}{
						{
							"id":       node.Config["uuid"],
							"alterId":  aid,
							"security": "auto",
						},
					},
				},
			},
		}
		outbound["streamSettings"] = buildStreamSettings(node)

	case "trojan":
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  node.Address,
					"port":     node.Port,
					"password": node.Config["password"],
				},
			},
		}
		outbound["streamSettings"] = buildStreamSettings(node)

	case "shadowsocks":
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  node.Address,
					"port":     node.Port,
					"method":   node.Config["method"],
					"password": node.Config["password"],
				},
			},
		}

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", node.Protocol)
	}

	return outbound, nil
}

func buildStreamSettings(node *ProxyNode) map[string]interface{} {
	ss := map[string]interface{}{
		"network":  node.Config["type"],
		"security": node.Config["security"],
	}

	security := node.Config["security"]
	fp := node.Config["fp"]
	if fp == "" {
		fp = "chrome"
	}

	sni := node.Config["sni"]
	if sni == "" {
		sni = node.Config["host"]
	}

	alpn := []string{"h2", "http/1.1"}
	if node.Config["alpn"] != "" {
		alpn = strings.Split(node.Config["alpn"], ",")
	}

	if security == "tls" {
		ss["security"] = "tls"
		ss["tlsSettings"] = map[string]interface{}{
			"serverName":    sni,
			"allowInsecure": true,
			"fingerprint":   fp,
			"alpn":          alpn,
		}
	} else if security == "reality" {
		ss["security"] = "reality"
		ss["realitySettings"] = map[string]interface{}{
			"serverName":  sni,
			"publicKey":   node.Config["pbk"],
			"shortId":     node.Config["sid"],
			"fingerprint": fp,
			"spiderX":     "/",
		}
	}

	// Network settings
	netType := node.Config["type"]
	path := node.Config["path"]
	host := node.Config["host"]

	if netType == "ws" {
		headers := map[string]string{}
		if host != "" {
			headers["Host"] = host
		}
		ss["wsSettings"] = map[string]interface{}{
			"path":    path,
			"headers": headers,
		}
	} else if netType == "grpc" {
		serviceName := node.Config["serviceName"]
		if serviceName == "" {
			serviceName = path
		}
		ss["grpcSettings"] = map[string]interface{}{
			"serviceName": serviceName,
			"multiMode":   false,
		}
	}

	return ss
}

// ============================================================================
// ПРОВЕРКА НОД
// ============================================================================

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
	for r := range resultChan {
		if r.Success {
			results = append(results, r)
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

	// Проверка SNI
	if len(sniWhitelist) > 0 {
		sni := node.Config["sni"]
		if sni == "" {
			atomic.AddInt32(&statsNoSNI, 1)
			return result
		}
		if !isTargetSNI(sni, sniWhitelist) {
			atomic.AddInt32(&statsSNIFail, 1)
			return result
		}
	}

	// Получаем порт
	port := int(atomic.AddInt32(&portCounter, 1))
	if port > MaxPortRange {
		atomic.StoreInt32(&portCounter, MinPortRange)
		port = MinPortRange
	}

	// Генерируем конфиг
	configPath, err := generateXrayConfig(node, port)
	if err != nil {
		atomic.AddInt32(&statsConfigFail, 1)
		return result
	}
	defer os.Remove(configPath)

	// Запускаем Xray
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./xray", "run", "-c", configPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		atomic.AddInt32(&statsConfigFail, 1)
		return result
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	time.Sleep(300 * time.Millisecond)

	// Проверяем связность
	if !checkConnectivity(port) {
		atomic.AddInt32(&statsConnectFail, 1)
		return result
	}

	// Измеряем скорость
	speed := measureSpeed(port)
	if speed < 1.0 {
		atomic.AddInt32(&statsSpeedFail, 1)
		return result
	}

	// Успех!
	atomic.AddInt32(&statsSuccess, 1)
	result.Speed = speed
	result.CountryID = getCountryCode(node.Address)
	result.Success = true
	return result
}

func checkConnectivity(port int) bool {
	dialer, err := goproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, goproxy.Direct)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial:            dialer.Dial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: TimeoutCheck,
	}

	for _, testURL := range testURLs {
		resp, err := client.Get(testURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 400 {
				return true
			}
		}
	}
	return false
}

func measureSpeed(port int) float64 {
	dialer, err := goproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, goproxy.Direct)
	if err != nil {
		return 0
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial:            dialer.Dial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: TimeoutSpeed,
	}

	for _, testURL := range speedTestURLs {
		start := time.Now()
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}

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
		resp.Body.Close()

		duration := time.Since(start).Seconds()
		if duration > 0.1 && downloaded > 1024 {
			return (float64(downloaded) * 8) / (duration * 1024 * 1024)
		}
	}
	return 0
}

func isTargetSNI(sni string, whitelist []string) bool {
	for _, w := range whitelist {
		if sni == w || strings.HasSuffix(sni, "."+w) {
			return true
		}
	}
	return false
}

func getCountryCode(address string) string {
	ips, err := net.LookupIP(address)
	if err != nil || len(ips) == 0 {
		if ip := net.ParseIP(address); ip != nil {
			ips = []net.IP{ip}
		} else {
			return "UN"
		}
	}

	if geoIPReader != nil {
		if record, err := geoIPReader.Country(ips[0]); err == nil {
			return record.Country.IsoCode
		}
	}
	return "UN"
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	fmt.Println("🚀 L7 Checker (Hybrid v2)")
	fmt.Println("=========================")

	inputFile := flag.String("input", "proxies.txt", "Input file")
	whitelistFile := flag.String("whitelist", "whitelist.txt", "SNI whitelist")
	flag.Parse()

	// Загружаем GeoIP
	var err error
	geoIPReader, err = geoip2.Open("GeoLite2-Country.mmdb")
	if err != nil {
		fmt.Println("⚠️ GeoIP not found")
	}

	// Загружаем whitelist
	sniWhitelist, err := readWhitelist(*whitelistFile)
	if err != nil {
		fmt.Printf("⚠️ Whitelist not found: %v\n", err)
		sniWhitelist = []string{}
	} else {
		fmt.Printf("📋 Loaded %d SNI domains\n", len(sniWhitelist))
	}

	// Загружаем ноды
	lines, err := readLines(*inputFile)
	if err != nil {
		fmt.Printf("❌ Error reading input: %v\n", err)
		os.Exit(1)
	}
	statsTotal = int32(len(lines))
	fmt.Printf("📄 Loaded %d lines\n", len(lines))

	// Парсим ноды
	nodes := []*ProxyNode{}
	for _, line := range lines {
		node, err := parseProxyLink(line)
		if err != nil {
			statsParseFail++
			continue
		}
		nodes = append(nodes, node)
	}
	fmt.Printf("✅ Parsed: %d, Failed: %d\n", len(nodes), statsParseFail)

	// Проверяем
	results := processNodes(nodes, sniWhitelist)
	saveResults(results)

	// Статистика
	fmt.Println("\n=========================")
	fmt.Println("📊 FINAL STATISTICS:")
	fmt.Printf("   📥 Total input:     %d\n", statsTotal)
	fmt.Printf("   ❌ Parse failed:    %d (%.1f%%)\n", statsParseFail, float64(statsParseFail)*100/float64(statsTotal))
	fmt.Printf("   🚫 No SNI:          %d\n", statsNoSNI)
	fmt.Printf("   🔒 SNI rejected:    %d\n", statsSNIFail)
	fmt.Printf("   ⚙️ Config failed:   %d\n", statsConfigFail)
	fmt.Printf("   🔌 Connect failed:  %d\n", statsConnectFail)
	fmt.Printf("   🐌 Speed too low:   %d\n", statsSpeedFail)
	fmt.Printf("   ✅ Success:         %d (%.1f%%)\n", statsSuccess, float64(statsSuccess)*100/float64(len(nodes)))
	fmt.Println("=========================")
}

func readWhitelist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var list []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			line = strings.TrimPrefix(line, ".")
			list = append(list, line)
		}
	}
	return list, nil
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

func saveResults(results []CheckResult) {
	ufFile, _ := os.Create("uf.txt")
	fastFile, _ := os.Create("fast.txt")
	normFile, _ := os.Create("norm.txt")
	defer ufFile.Close()
	defer fastFile.Close()
	defer normFile.Close()

	for _, r := range results {
		if !r.Success {
			continue
		}

		flag := countryFlags[r.CountryID]
		if flag == "" {
			flag = "🌐"
		}
		name := r.Node.Name
		if name == "" {
			name = fmt.Sprintf("%s %s", flag, r.CountryID)
		}

		var speedTag string
		var file *os.File
		if r.Speed >= UltraFastSpeed {
			speedTag = " | YT | UF"
			file = ufFile
		} else if r.Speed >= FastSpeed {
			speedTag = " | YT | FAST"
			file = fastFile
		} else {
			speedTag = " | YT | NORM"
			file = normFile
		}

		link := strings.Split(r.Node.RawLink, "#")[0]
		fmt.Fprintf(file, "%s#%s%s\n", link, url.QueryEscape(name), speedTag)
	}

	ufCount, _ := countLines("uf.txt")
	fastCount, _ := countLines("fast.txt")
	normCount, _ := countLines("norm.txt")

	fmt.Printf("\n📊 Saved: UF=%d, FAST=%d, NORM=%d\n", ufCount, fastCount, normCount)
}

func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count, nil
}
 
