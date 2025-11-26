package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	listenAddr    string
	forwardAddr   string
	ipAddr        string
	token         string
	connectionNum int // 单地址并发数

	// ECH/DNS 参数
	dnsServer string
	echDomain string

	// 运行期缓存
	echListMu sync.RWMutex
	echList   []byte

	// 连接池
	echPool *ECHPool
)

func init() {
	flag.StringVar(&listenAddr, "l", "", "监听地址 (例如 proxy://0.0.0.0:1080)")
	flag.StringVar(&forwardAddr, "f", "", "服务端地址 (支持逗号分隔)")
	flag.StringVar(&ipAddr, "ip", "", "指定解析 IP (仅客户端)")
	flag.StringVar(&token, "token", "", "认证 Token")
	flag.StringVar(&dnsServer, "dns", "119.29.29.29:53", "DNS 服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")
	flag.IntVar(&connectionNum, "n", 7, "单地址并发通道数")

	// 兼容性占位 (避免 Docker 报错)
	var dummy string
	flag.StringVar(&dummy, "cert", "", "ignored")
	flag.StringVar(&dummy, "key", "", "ignored")
	flag.StringVar(&dummy, "cidr", "", "ignored")
}

func main() {
	flag.Parse()

	// 解析服务端地址
	var forwardAddrs []string
	if forwardAddr != "" {
		parts := strings.Split(forwardAddr, ",")
		for _, p := range parts {
			t := strings.TrimSpace(p)
			if t != "" {
				forwardAddrs = append(forwardAddrs, t)
			}
		}
	}

	if strings.HasPrefix(listenAddr, "ws://") || strings.HasPrefix(listenAddr, "wss://") {
		log.Fatal("当前版本仅支持客户端模式")
	}

	if strings.HasPrefix(listenAddr, "tcp://") {
		if len(forwardAddrs) == 0 {
			log.Fatal("客户端模式必须指定服务端地址 (-f)")
		}
		if err := prepareECH(); err != nil {
			log.Fatalf("获取 ECH 失败: %v", err)
		}
		runTCPClient(listenAddr, forwardAddrs)
		return
	}
	if strings.HasPrefix(listenAddr, "proxy://") {
		if len(forwardAddrs) == 0 {
			log.Fatal("代理模式必须指定服务端地址 (-f)")
		}
		if err := prepareECH(); err != nil {
			log.Fatalf("获取 ECH 失败: %v", err)
		}
		runProxyServer(listenAddr, forwardAddrs)
		return
	}
	log.Fatal("监听地址格式错误")
}

// ======================== ECH Logic ========================

const typeHTTPS = 65

func prepareECH() error {
	for {
		b64, err := queryHTTPSRecord(echDomain, dnsServer)
		if err != nil || b64 == "" {
			time.Sleep(2 * time.Second)
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		echListMu.Lock()
		echList = raw
		echListMu.Unlock()
		return nil
	}
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH not loaded")
	}
	return echList, nil
}

func refreshECH() {
	prepareECH()
}

func buildTLSConfigWithECH(sn string, el []byte) (*tls.Config, error) {
	roots, _ := x509.SystemCertPool()
	return &tls.Config{
		MinVersion:                          tls.VersionTLS13,
		ServerName:                          sn,
		EncryptedClientHelloConfigList:      el,
		EncryptedClientHelloRejectionVerify: func(_ tls.ConnectionState) error { return errors.New("ECH rejected") },
		RootCAs:                             roots,
	}, nil
}

func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	q := make([]byte, 0, 512)
	q = append(q, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, l := range strings.Split(domain, ".") {
		q = append(q, byte(len(l)))
		q = append(q, []byte(l)...)
	}
	q = append(q, 0, byte(typeHTTPS>>8), byte(typeHTTPS), 0, 1)

	c, err := net.Dial("udp", dnsServer)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(q)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	return parseDNSResponse(buf[:n])
}

func parseDNSResponse(b []byte) (string, error) {
	if len(b) < 12 {
		return "", fmt.Errorf("invalid")
	}
	ancount := binary.BigEndian.Uint16(b[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("no answer")
	}
	off := 12
	for off < len(b) && b[off] != 0 {
		off += int(b[off]) + 1
	}
	off += 5
	for i := 0; i < int(ancount); i++ {
		if off >= len(b) {
			break
		}
		if b[off]&0xC0 == 0xC0 {
			off += 2
		} else {
			for off < len(b) && b[off] != 0 {
				off += int(b[off]) + 1
			}
			off++
		}
		if offsetCheck(off + 10, len(b)) {
			break
		}
		rtype := binary.BigEndian.Uint16(b[off : off+2])
		off += 8
		dlen := binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		if offsetCheck(off+int(dlen), len(b)) {
			break
		}
		if rtype == typeHTTPS {
			return parseHTTPSRecord(b[off : off+int(dlen)]), nil
		}
		off += int(dlen)
	}
	return "", nil
}

func offsetCheck(need, total int) bool {
	return need > total
}

func parseHTTPSRecord(d []byte) string {
	if len(d) < 2 {
		return ""
	}
	off := 2
	if off < len(d) && d[off] == 0 {
		off++
	} else {
		for off < len(d) && d[off] != 0 {
			off += int(d[off]) + 1
		}
		off++
	}
	for off+4 <= len(d) {
		k := binary.BigEndian.Uint16(d[off : off+2])
		l := binary.BigEndian.Uint16(d[off+2 : off+4])
		off += 4
		if off+int(l) > len(d) {
			break
		}
		v := d[off : off+int(l)]
		off += int(l)
		if k == 5 {
			return base64.StdEncoding.EncodeToString(v)
		}
	}
	return ""
}

// ======================== ECH Pool (Racing) ========================

type ECHPool struct {
	wsServerAddrs []string
	perAddrNum    int
	totalNum      int
	conns         []*websocket.Conn
	locks         []sync.Mutex
	tcpMap        sync.Map
	chMap         sync.Map
	connected     sync.Map
}

func NewECHPool(addrs []string, n int) *ECHPool {
	total := len(addrs) * n
	return &ECHPool{
		wsServerAddrs: addrs,
		perAddrNum:    n,
		totalNum:      total,
		conns:         make([]*websocket.Conn, total),
		locks:         make([]sync.Mutex, total),
	}
}

func (p *ECHPool) Start() {
	globalIdx := 0
	for _, addr := range p.wsServerAddrs {
		for i := 0; i < p.perAddrNum; i++ {
			go p.maintainConn(globalIdx, addr)
			globalIdx++
		}
	}
	log.Printf("[连接池] 启动: 总通道%d (地址%d * 并发%d)", p.totalNum, len(p.wsServerAddrs), p.perAddrNum)
}

func (p *ECHPool) maintainConn(idx int, addr string) {
	for {
		ws, err := dialWebSocketWithECH(addr, 2)
		if err != nil {
			log.Printf("[通道-%d] 连接 %s 失败, 2s重试", idx, addr)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("[通道-%d] 已连接到 %s", idx, addr)
		p.conns[idx] = ws
		p.handleConn(idx, ws)
		time.Sleep(time.Second)
	}
}

func (p *ECHPool) RegisterAndClaim(connID, target, first string, tcpConn net.Conn) {
	p.tcpMap.Store(connID, tcpConn)
	ch := make(chan bool, 1)
	p.connected.Store(connID, ch)
	p.chMap.Store(connID+"_META", fmt.Sprintf("%s|%s", target, first))

	for i := 0; i < p.totalNum; i++ {
		ws := p.conns[i]
		if ws == nil {
			continue
		}
		go func(idx int, w *websocket.Conn) {
			p.locks[idx].Lock()
			w.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("CLAIM:%s|%d", connID, idx)))
			p.locks[idx].Unlock()
		}(i, ws)
	}
}

func (p *ECHPool) WaitConnected(connID string, timeout time.Duration) bool {
	v, ok := p.connected.Load(connID)
	if !ok {
		return false
	}
	select {
	case <-v.(chan bool):
		return true
	case <-time.After(timeout):
		return false
	}
}

func (p *ECHPool) SendData(connID string, data []byte) error {
	v, ok := p.chMap.Load(connID)
	if !ok {
		return fmt.Errorf("no channel")
	}
	idx := v.(int)
	p.locks[idx].Lock()
	ws := p.conns[idx]
	if ws == nil {
		p.locks[idx].Unlock()
		return fmt.Errorf("closed")
	}
	err := ws.WriteMessage(websocket.TextMessage, []byte("DATA:"+connID+"|"+string(data)))
	p.locks[idx].Unlock()
	return err
}

func (p *ECHPool) SendClose(connID string) {
	v, ok := p.chMap.Load(connID)
	if !ok {
		return
	}
	idx := v.(int)
	p.locks[idx].Lock()
	ws := p.conns[idx]
	if ws != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
	}
	p.locks[idx].Unlock()
}

func (p *ECHPool) handleConn(idx int, ws *websocket.Conn) {
	ws.SetPingHandler(func(d string) error {
		p.locks[idx].Lock()
		defer p.locks[idx].Unlock()
		return ws.WriteMessage(websocket.PongMessage, []byte(d))
	})
	go func() {
		tk := time.NewTicker(10 * time.Second)
		defer tk.Stop()
		for range tk.C {
			p.locks[idx].Lock()
			if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				p.locks[idx].Unlock()
				return
			}
			p.locks[idx].Unlock()
		}
	}()

	for {
		mt, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.BinaryMessage {
			if len(msg) > 5 && string(msg[:5]) == "DATA:" {
				parts := strings.SplitN(string(msg[5:]), "|", 2)
				if len(parts) == 2 {
					if c, ok := p.tcpMap.Load(parts[0]); ok {
						c.(net.Conn).Write([]byte(parts[1]))
					}
				}
			}
			continue
		}
		if mt == websocket.TextMessage {
			s := string(msg)
			if strings.HasPrefix(s, "CLAIM_ACK:") {
				parts := strings.SplitN(s[10:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					if _, loaded := p.chMap.LoadOrStore(connID, idx); !loaded {
						if meta, ok := p.chMap.Load(connID + "_META"); ok {
							ms := strings.SplitN(meta.(string), "|", 2)
							p.locks[idx].Lock()
							ws.WriteMessage(websocket.TextMessage, []byte("TCP:"+connID+"|"+ms[0]+"|"+ms[1]))
							p.locks[idx].Unlock()
							p.chMap.Delete(connID + "_META")
						}
					}
				}
			} else if strings.HasPrefix(s, "CONNECTED:") {
				id := strings.TrimPrefix(s, "CONNECTED:")
				if ch, ok := p.connected.Load(id); ok {
					select {
					case ch.(chan bool) <- true:
					default:
					}
				}
			} else if strings.HasPrefix(s, "CLOSE:") {
				id := strings.TrimPrefix(s, "CLOSE:")
				if c, ok := p.tcpMap.Load(id); ok {
					c.(net.Conn).Close()
					p.tcpMap.Delete(id)
					p.chMap.Delete(id)
				}
			}
		}
	}
}

// ======================== Client Runners ========================

func runTCPClient(listen string, addrs []string) {
	listen = strings.TrimPrefix(listen, "tcp://")
	parts := strings.Split(listen, "/")
	if len(parts) < 2 {
		log.Fatal("TCP 模式必须指定目标地址: tcp://listen/target")
	}
	
	echPool = NewECHPool(addrs, connectionNum)
	echPool.Start()

	l, err := net.Listen("tcp", parts[0])
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("TCP 监听: %s -> %s", parts[0], parts[1])

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			id := uuid.New().String()
			p := make([]byte, 32768)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _ := c.Read(p)
			c.SetReadDeadline(time.Time{})
			
			// 如果 n=0 (连接即断开), 仍尝试建立连接但数据为空
			echPool.RegisterAndClaim(id, parts[1], string(p[:n]), c)
			if !echPool.WaitConnected(id, 5*time.Second) {
				c.Close()
				return
			}
			buf := make([]byte, 32768)
			for {
				n, err := c.Read(buf)
				if err != nil {
					echPool.SendClose(id)
					return
				}
				echPool.SendData(id, buf[:n])
			}
		}()
	}
}

func runProxyServer(addr string, addrs []string) {
	config, _ := parseProxyAddr(addr)
	l, err := net.Listen("tcp", config.Host)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("代理启动: %s", config.Host)

	echPool = NewECHPool(addrs, connectionNum)
	echPool.Start()

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go handleProxyConnection(c, config)
	}
}

func dialWebSocketWithECH(wsAddr string, retries int) (*websocket.Conn, error) {
	u, _ := url.Parse(wsAddr)
	if u.Scheme != "wss" {
		return nil, fmt.Errorf("must use wss")
	}
	sn := u.Hostname()
	for i := 0; i <= retries; i++ {
		el, err := getECHList()
		if err != nil {
			refreshECH()
			continue
		}
		cfg, _ := buildTLSConfigWithECH(sn, el)
		dialer := websocket.Dialer{
			TLSClientConfig:  cfg,
			HandshakeTimeout: 5 * time.Second,
			Subprotocols:     []string{token},
			ReadBufferSize:   65536,
			WriteBufferSize:  65536,
		}
		if ipAddr != "" {
			dialer.NetDial = func(network, addr string) (net.Conn, error) {
				// 修复: Cloudflare WSS 可能省略端口, 手动补全
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					// 假设是 443
					port = "443"
				}
				return net.DialTimeout(network, net.JoinHostPort(ipAddr, port), 5*time.Second)
			}
		}
		ws, _, err := dialer.Dial(wsAddr, nil)
		if err != nil {
			if strings.Contains(err.Error(), "ECH") {
				refreshECH()
			}
			continue
		}
		return ws, nil
	}
	return nil, fmt.Errorf("failed")
}

// ======================== Proxy Helpers ========================

type ProxyConfig struct {
	Username, Password, Host string
}

func parseProxyAddr(addr string) (*ProxyConfig, error) {
	addr = strings.TrimPrefix(addr, "proxy://")
	c := &ProxyConfig{}
	if strings.Contains(addr, "@") {
		pts := strings.SplitN(addr, "@", 2)
		up := strings.SplitN(pts[0], ":", 2)
		if len(up) == 2 {
			c.Username, c.Password = up[0], up[1]
		}
		c.Host = pts[1]
	} else {
		c.Host = addr
	}
	return c, nil
}

func validateProxyAuth(authHeader, username, password string) bool {
	if authHeader == "" {
		return false
	}
	if !strings.HasPrefix(authHeader, "Basic ") {
		return false
	}
	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	return len(parts) == 2 && parts[0] == username && parts[1] == password
}

func handleProxyConnection(conn net.Conn, cfg *ProxyConfig) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	if b[0] == 0x05 {
		handleSOCKS5(conn, cfg)
	} else {
		handleHTTP(conn, cfg, b[0])
	}
}

func handleSOCKS5(conn net.Conn, cfg *ProxyConfig) {
	conn.Write([]byte{0x05, 0x00})
	buf := make([]byte, 262)
	io.ReadFull(conn, buf[:4])
	if buf[1] != 0x01 {
		return
	}
	var target string
	switch buf[3] {
	case 1:
		io.ReadFull(conn, buf[:4])
		target = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3:
		io.ReadFull(conn, buf[:1])
		l := int(buf[0])
		io.ReadFull(conn, buf[:l])
		target = string(buf[:l])
	}
	io.ReadFull(conn, buf[:2])
	target += fmt.Sprintf(":%d", int(buf[0])<<8|int(buf[1]))

	id := uuid.New().String()
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	echPool.RegisterAndClaim(id, target, "", conn)
	if !echPool.WaitConnected(id, 5*time.Second) {
		return
	}
	defer echPool.SendClose(id)
	
	b := make([]byte, 32768)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return
		}
		echPool.SendData(id, b[:n])
	}
}

func handleHTTP(conn net.Conn, cfg *ProxyConfig, first byte) {
	buf := bytes.NewBuffer([]byte{first})
	p := make([]byte, 4096)
	n, _ := conn.Read(p)
	full := append(buf.Bytes(), p[:n]...)

	lines := strings.Split(string(full), "\r\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) < 2 {
		return
	}
	method := parts[0]
	urlStr := parts[1]

	headers := make(map[string]string)
	for _, l := range lines[1:] {
		if l == "" {
			break
		}
		hp := strings.SplitN(l, ":", 2)
		if len(hp) == 2 {
			headers[strings.TrimSpace(hp[0])] = strings.TrimSpace(hp[1])
		}
	}

	if cfg.Username != "" {
		if !validateProxyAuth(headers["Proxy-Authorization"], cfg.Username, cfg.Password) {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"))
			return
		}
	}

	var target string
	if method == "CONNECT" {
		target = urlStr
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		full = nil
	} else {
		u, err := url.Parse(urlStr)
		if err != nil || u == nil {
			// URL 解析失败，无法继续转发
			return
		}
		target = u.Host
		if target == "" {
			for _, l := range lines {
				if strings.HasPrefix(l, "Host:") {
					target = strings.TrimSpace(strings.TrimPrefix(l, "Host:"))
					break
				}
			}
		}
		if !strings.Contains(target, ":") {
			target += ":80"
		}
	}

	id := uuid.New().String()
	echPool.RegisterAndClaim(id, target, string(full), conn)
	if !echPool.WaitConnected(id, 5*time.Second) {
		return
	}
	defer echPool.SendClose(id)

	b := make([]byte, 32768)
	for {
		n, err := conn.Read(b)
		if err != nil {
			return
		}
		echPool.SendData(id, b[:n])
	}
}
