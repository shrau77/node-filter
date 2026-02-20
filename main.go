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
        BatchSize       = 50  // Нод на один процесс Xray
        MaxConcurrent   = 10  // Максимум параллельных Xray процессов
        MinPortRange    = 20000
        MaxPortRange    = 30000
        XrayURL         = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
        GeoIPURL        = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
        TimeoutCheck    = 10 * time.Second
        TimeoutSpeed    = 15 * time.Second
        UltraFastSpeed  = 3.5
        FastSpeed       = 2.5
        SpeedTestSize   = 1 * 1024 * 1024
)

// Множественные speed test URL (как в a2ray.py)
var speedTestURLs = []string{
        "https://speed.cloudflare.com/__down?bytes=10000000",
        "https://proof.ovh.net/files/10Mb.dat",
        "https://speed.hetzner.de/10MB.bin",
        "https://yandex.ru/internet/api/v0/measure/download?size=10000000",
}

// Тестовые URL для проверки связности
var testURLs = []string{
        "http://gstatic.com/generate_204",
        "http://cp.cloudflare.com/generate_204",
        "https://www.google.com/generate_204",
}

// Regex для валидации Reality (как в a2ray.py)
var (
        RealityPBKRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{43,44}$`)
        RealitySIDRegex = regexp.MustCompile(`^[0-9a-fA-F]{0,32}$`)
        UUIDRegex       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
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
        Error     string
}

type XrayConfig struct {
        Log       map[string]interface{}   `json:"log"`
        Inbounds  []map[string]interface{} `json:"inbounds"`
        Outbounds []map[string]interface{} `json:"outbounds"`
        Routing   map[string]interface{}   `json:"routing"`
}

// ============================================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ============================================================================

var (
        geoIPReader *geoip2.Reader
        portCounter int32 = MinPortRange

        // Статистика
        statsTotal      int32
        statsParseFail  int32
        statsNoSNI      int32
        statsSNIFail    int32
        statsConfigFail int32
        statsConnectFail int32
        statsSpeedFail  int32
        statsSuccess    int32

        countryFlags = map[string]string{
                "US": "🇺🇸", "GB": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "NL": "🇳🇱",
                "CA": "🇨🇦", "JP": "🇯🇵", "KR": "🇰🇷", "SG": "🇸🇬", "HK": "🇭🇰",
                "TW": "🇹🇼", "AU": "🇦🇺", "RU": "🇷🇺", "CN": "🇨🇳", "IN": "🇮🇳",
                "BR": "🇧🇷", "TR": "🇹🇷", "SE": "🇸🇪", "PL": "🇵🇱", "IT": "🇮🇹",
                "ES": "🇪🇸", "CH": "🇨🇭", "FI": "🇫🇮", "NO": "🇳🇴", "DK": "🇩🇰",
        }
)

// ============================================================================
// ВАЛИДАЦИЯ (как в a2ray.py)
// ============================================================================

func isValidUUID(uuid string) bool {
        return UUIDRegex.MatchString(uuid)
}

func isValidRealityPBK(pbk string) bool {
        return RealityPBKRegex.MatchString(pbk)
}

func isValidRealitySID(sid string) bool {
        if sid == "" {
                return true // Пустой SID допустим
        }
        // SID должен быть hex и чётной длины
        if len(sid)%2 != 0 {
                return false
        }
        return RealitySIDRegex.MatchString(sid)
}

func isValidPort(port int) bool {
        return port > 0 && port <= 65535
}

// ============================================================================
// ПАРСИНГ (улучшенный, без жестких регулярок)
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
        } else if strings.HasPrefix(link, "hysteria2://") || strings.HasPrefix(link, "hy2://") {
                return parseHysteria2(link)
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

        // Парсим через url.Parse (надёжнее регулярок)
        parsed, err := url.Parse(mainPart)
        if err != nil {
                return nil, err
        }

        if parsed.User == nil {
                return nil, fmt.Errorf("no UUID")
        }

        node.Config["uuid"] = parsed.User.Username()
        if !isValidUUID(node.Config["uuid"]) {
                return nil, fmt.Errorf("invalid UUID")
        }

        // Адрес и порт
        host := parsed.Hostname()
        portStr := parsed.Port()
        if host == "" || portStr == "" {
                return nil, fmt.Errorf("missing host/port")
        }
        node.Address = host
        node.Port, _ = strconv.Atoi(portStr)
        if !isValidPort(node.Port) {
                return nil, fmt.Errorf("invalid port")
        }

        // Query параметры
        q := parsed.Query()
        node.Config["security"] = getParam(q, "security", "none")
        node.Config["encryption"] = getParam(q, "encryption", "none")
        node.Config["type"] = getParam(q, "type", "tcp")
        node.Config["sni"] = getParam(q, "sni", "")
        node.Config["fp"] = getParam(q, "fp", "chrome")
        node.Config["flow"] = getParam(q, "flow", "")
        node.Config["path"] = getParam(q, "path", "")
        node.Config["host"] = getParam(q, "host", "")
        node.Config["serviceName"] = getParam(q, "serviceName", "")
        node.Config["mode"] = getParam(q, "mode", "")
        node.Config["alpn"] = getParam(q, "alpn", "")

        // Reality параметры
        pbk := getParam(q, "pbk", "")
        sid := getParam(q, "sid", "")

        // Валидация Reality
        if node.Config["security"] == "reality" {
                if !isValidRealityPBK(pbk) {
                        return nil, fmt.Errorf("invalid Reality publicKey")
                }
                if !isValidRealitySID(sid) {
                        sid = "" // Сбрасываем невалидный
                }
        }
        node.Config["pbk"] = pbk
        node.Config["sid"] = sid

        // Если есть pbk но security не reality - исправляем
        if pbk != "" && node.Config["security"] != "reality" {
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

        parsed, err := url.Parse(mainPart)
        if err != nil {
                return nil, err
        }

        if parsed.User == nil {
                return nil, fmt.Errorf("no password")
        }

        node.Config["password"] = parsed.User.Username()
        node.Address = parsed.Hostname()
        node.Port, _ = strconv.Atoi(parsed.Port())
        if !isValidPort(node.Port) {
                return nil, fmt.Errorf("invalid port")
        }

        q := parsed.Query()
        node.Config["security"] = getParam(q, "security", "tls")
        node.Config["sni"] = getParam(q, "sni", getParam(q, "peer", ""))
        node.Config["type"] = getParam(q, "type", "tcp")
        node.Config["fp"] = getParam(q, "fp", "chrome")

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

        // Формат: method:password@host:port
        if idx := strings.Index(mainPart, "@"); idx != -1 {
                userInfo := mainPart[:idx]
                serverPart := mainPart[idx+1:]

                // Декодируем userInfo если нужно
                var decoded string
                if strings.Contains(userInfo, ":") {
                        decoded = userInfo
                } else {
                        // Base64 декодирование
                        if b, err := base64.StdEncoding.DecodeString(userInfo + "=="); err == nil {
                                decoded = string(b)
                        } else if b, err := base64.RawURLEncoding.DecodeString(userInfo); err == nil {
                                decoded = string(b)
                        } else {
                                decoded = userInfo
                        }
                }

                parts := strings.SplitN(decoded, ":", 2)
                if len(parts) == 2 {
                        node.Config["method"] = parts[0]
                        node.Config["password"] = parts[1]
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

func parseHysteria2(link string) (*ProxyNode, error) {
        node := &ProxyNode{RawLink: link, Protocol: "hysteria2", Config: make(map[string]string)}

        link = strings.Replace(link, "hy2://", "hysteria2://", 1)
        link = strings.TrimPrefix(link, "hysteria2://")

        mainPart := link
        if idx := strings.Index(link, "#"); idx != -1 {
                mainPart = link[:idx]
                node.Name, _ = url.QueryUnescape(link[idx+1:])
        }

        parsed, err := url.Parse("hysteria2://" + mainPart)
        if err != nil {
                return nil, err
        }

        if parsed.User != nil {
                node.Config["password"] = parsed.User.Username()
        }
        node.Address = parsed.Hostname()
        node.Port, _ = strconv.Atoi(parsed.Port())
        if !isValidPort(node.Port) {
                return nil, fmt.Errorf("invalid port")
        }

        q := parsed.Query()
        node.Config["sni"] = getParam(q, "sni", "")
        node.Config["obfs"] = getParam(q, "obfs", "none")
        node.Config["obfs-password"] = getParam(q, "obfs-password", "")

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
                return nil, fmt.Errorf("invalid vmess base64")
        }

        var data map[string]interface{}
        if err := json.Unmarshal([]byte(decoded), &data); err != nil {
                return nil, err
        }

        node.Config["uuid"] = getString(data, "id")
        if !isValidUUID(node.Config["uuid"]) {
                return nil, fmt.Errorf("invalid UUID")
        }

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
        node.Name = getString(data, "ps")

        if node.Address == "" || node.Port == 0 {
                return nil, fmt.Errorf("missing host/port")
        }

        return node, nil
}

func getParam(q url.Values, key, def string) string {
        if v := q.Get(key); v != "" {
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
// ГЕНЕРАЦИЯ КОНФИГА XRAY (С БАТЧИНГОМ)
// ============================================================================

func createBatchConfig(nodes []*ProxyNode, startPort int) (string, []int, error) {
        inbounds := []map[string]interface{}{}
        outbounds := []map[string]interface{}{}
        rules := []map[string]interface{}{}
        ports := []int{}

        for i, node := range nodes {
                port := startPort + i
                inTag := fmt.Sprintf("in_%d", port)
                outTag := fmt.Sprintf("out_%d", port)

                // Inbound
                inbounds = append(inbounds, map[string]interface{}{
                        "port":     port,
                        "listen":   "127.0.0.1",
                        "protocol": "socks",
                        "tag":      inTag,
                        "settings": map[string]interface{}{"udp": true},
                })

                // Outbound
                outbound, err := createOutbound(node, outTag)
                if err != nil {
                        continue
                }
                outbounds = append(outbounds, outbound)

                // Rule
                rules = append(rules, map[string]interface{}{
                        "type":        "field",
                        "inboundTag":  []string{inTag},
                        "outboundTag": outTag,
                })

                ports = append(ports, port)
        }

        if len(outbounds) == 0 {
                return "", nil, fmt.Errorf("no valid outbounds")
        }

        config := map[string]interface{}{
                "log": map[string]interface{}{"loglevel": "none"},
                "inbounds":  inbounds,
                "outbounds": outbounds,
                "routing": map[string]interface{}{
                        "domainStrategy": "AsIs",
                        "rules":          rules,
                },
        }

        data, _ := json.Marshal(config)
        configPath := fmt.Sprintf("batch_%d.json", startPort)
        os.WriteFile(configPath, data, 0644)

        return configPath, ports, nil
}

func createOutbound(node *ProxyNode, tag string) (map[string]interface{}, error) {
        outbound := map[string]interface{}{
                "protocol": node.Protocol,
                "tag":      tag,
        }

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
                outbound["settings"] = map[string]interface{}{
                        "vnext": []map[string]interface{}{
                                {
                                        "address": node.Address,
                                        "port":    node.Port,
                                        "users": []map[string]interface{}{
                                                {
                                                        "id":       node.Config["uuid"],
                                                        "alterId":  node.Config["aid"],
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

        case "hysteria2":
                outbound["settings"] = map[string]interface{}{
                        "vnext": []map[string]interface{}{
                                {
                                        "address": node.Address,
                                        "port":    node.Port,
                                        "users": []map[string]interface{}{
                                                {"password": node.Config["password"]},
                                        },
                                },
                        },
                }
                outbound["streamSettings"] = map[string]interface{}{
                        "security": "tls",
                        "tlsSettings": map[string]interface{}{
                                "serverName":    node.Config["sni"],
                                "allowInsecure": true,
                                "fingerprint":   "chrome",
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

        // ALPN
        var alpn []string
        if node.Config["alpn"] != "" {
                alpn = strings.Split(node.Config["alpn"], ",")
        } else {
                alpn = []string{"h2", "http/1.1"}
        }

        if security == "tls" {
                ss["tlsSettings"] = map[string]interface{}{
                        "serverName":    sni,
                        "allowInsecure": true,
                        "fingerprint":   fp,
                        "alpn":          alpn,
                }
        } else if security == "reality" {
                ss["realitySettings"] = map[string]interface{}{
                        "serverName":  sni,
                        "publicKey":   node.Config["pbk"],
                        "shortId":     node.Config["sid"],
                        "fingerprint": fp,
                        "spiderX":     "/",
                }
        }

        // Network-specific settings
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

func checkBatch(nodes []*ProxyNode, sniWhitelist []string) []CheckResult {
        results := make([]CheckResult, len(nodes))

        // Фильтруем по SNI
        validNodes := []*ProxyNode{}
        validIndices := []int{}
        for i, node := range nodes {
                // Проверка SNI
                if len(sniWhitelist) > 0 {
                        sni := node.Config["sni"]
                        if sni == "" {
                                atomic.AddInt32(&statsNoSNI, 1)
                                results[i] = CheckResult{Node: node, Success: false, Error: "no SNI"}
                                continue
                        }
                        if !isTargetSNI(sni, sniWhitelist) {
                                atomic.AddInt32(&statsSNIFail, 1)
                                results[i] = CheckResult{Node: node, Success: false, Error: "SNI not in whitelist"}
                                continue
                        }
                }
                validNodes = append(validNodes, node)
                validIndices = append(validIndices, i)
        }

        if len(validNodes) == 0 {
                return results
        }

        // Создаём батч-конфиг
        startPort := int(atomic.AddInt32(&portCounter, int32(len(validNodes))))
        configPath, ports, err := createBatchConfig(validNodes, startPort)
        if err != nil {
                atomic.AddInt32(&statsConfigFail, int32(len(validNodes)))
                for _, idx := range validIndices {
                        results[idx] = CheckResult{Node: nodes[idx], Success: false, Error: "config error"}
                }
                return results
        }
        defer os.Remove(configPath)

        // Запускаем Xray
        ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
        defer cancel()

        cmd := exec.CommandContext(ctx, "./xray", "run", "-c", configPath)
        cmd.Stdout = nil
        cmd.Stderr = nil
        if err := cmd.Start(); err != nil {
                atomic.AddInt32(&statsConfigFail, int32(len(validNodes)))
                for _, idx := range validIndices {
                        results[idx] = CheckResult{Node: nodes[idx], Success: false, Error: "xray start error"}
                }
                return results
        }
        defer func() {
                cmd.Process.Kill()
                cmd.Wait()
        }()

        time.Sleep(500 * time.Millisecond)

        // Проверяем каждую ноду
        var wg sync.WaitGroup
        var mu sync.Mutex

        for i, node := range validNodes {
                wg.Add(1)
                go func(idx int, n *ProxyNode, port int) {
                        defer wg.Done()

                        // Проверяем связность
                        if !checkConnectivity(port) {
                                atomic.AddInt32(&statsConnectFail, 1)
                                mu.Lock()
                                results[validIndices[idx]] = CheckResult{Node: n, Success: false, Error: "connect failed"}
                                mu.Unlock()
                                return
                        }

                        // Измеряем скорость
                        speed := measureSpeed(port)
                        if speed < 1.0 {
                                atomic.AddInt32(&statsSpeedFail, 1)
                                mu.Lock()
                                results[validIndices[idx]] = CheckResult{Node: n, Success: false, Error: "speed too low"}
                                mu.Unlock()
                                return
                        }

                        // Успех!
                        atomic.AddInt32(&statsSuccess, 1)
                        country := getCountryCode(n.Address)
                        mu.Lock()
                        results[validIndices[idx]] = CheckResult{
                                Node:      n,
                                Speed:     speed,
                                CountryID: country,
                                Success:   true,
                        }
                        mu.Unlock()
                }(i, node, ports[i])
        }

        wg.Wait()
        return results
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

        // Пробуем несколько URL
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

        // Пробуем разные speed test URL
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
        fmt.Println("🚀 L7 Checker (Hybrid Edition - Batch Mode)")
        fmt.Println("============================================")

        inputFile := flag.String("input", "proxies.txt", "Input file")
        whitelistFile := flag.String("whitelist", "whitelist.txt", "SNI whitelist")
        flag.Parse()

        // Загружаем GeoIP
        var err error
        geoIPReader, err = geoip2.Open("GeoLite2-Country.mmdb")
        if err != nil {
                fmt.Println("⚠️ GeoIP not found, country detection disabled")
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
        nodes, err := readNodes(*inputFile)
        if err != nil {
                fmt.Printf("❌ Error reading input: %v\n", err)
                os.Exit(1)
        }

        statsTotal = int32(len(nodes))
        fmt.Printf("📄 Loaded %d nodes\n", len(nodes))

        // Парсим ноды
        parsedNodes := []*ProxyNode{}
        for _, raw := range nodes {
                node, err := parseProxyLink(raw)
                if err != nil {
                        statsParseFail++
                        continue
                }
                parsedNodes = append(parsedNodes, node)
        }
        fmt.Printf("✅ Parsed: %d, Failed: %d\n", len(parsedNodes), statsParseFail)

        // Разбиваем на батчи и проверяем
        allResults := []CheckResult{}
        for i := 0; i < len(parsedNodes); i += BatchSize {
                end := i + BatchSize
                if end > len(parsedNodes) {
                        end = len(parsedNodes)
                }
                batch := parsedNodes[i:end]

                fmt.Printf("⏳ Checking batch %d-%d...\n", i+1, end)
                results := checkBatch(batch, sniWhitelist)
                allResults = append(allResults, results...)
        }

        // Сохраняем результаты
        saveResults(allResults)

        // Статистика
        fmt.Println("\n============================================")
        fmt.Println("📊 FINAL STATISTICS:")
        fmt.Printf("   📥 Total input:     %d\n", statsTotal)
        fmt.Printf("   ❌ Parse failed:    %d (%.1f%%)\n", statsParseFail, float64(statsParseFail)*100/float64(statsTotal))
        fmt.Printf("   🚫 No SNI:          %d\n", statsNoSNI)
        fmt.Printf("   🔒 SNI rejected:    %d\n", statsSNIFail)
        fmt.Printf("   ⚙️ Config failed:   %d\n", statsConfigFail)
        fmt.Printf("   🔌 Connect failed:  %d\n", statsConnectFail)
        fmt.Printf("   🐌 Speed too low:   %d\n", statsSpeedFail)
        fmt.Printf("   ✅ Success:         %d (%.1f%%)\n", statsSuccess, float64(statsSuccess)*100/float64(len(parsedNodes)))
        fmt.Println("============================================")
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

func readNodes(filename string) ([]string, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, err
        }
        defer file.Close()

        var nodes []string
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line != "" && !strings.HasPrefix(line, "#") {
                        nodes = append(nodes, line)
                }
        }
        return nodes, nil
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
 
