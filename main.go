package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
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
	certFile      string
	keyFile       string
	token         string
	cidrs         string
	connectionNum int // 这里代表“每个地址的并发数”

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
	flag.StringVar(&forwardAddr, "f", "", "服务端地址 (支持逗号分隔: wss://a.com,wss://b.com)")
	flag.StringVar(&ipAddr, "ip", "", "指定解析 IP (仅客户端)")
	flag.StringVar(&certFile, "cert", "", "证书路径 (仅服务端)")
	flag.StringVar(&keyFile, "key", "", "私钥路径 (仅服务端)")
	flag.StringVar(&token, "token", "", "认证 Token")
	flag.StringVar(&cidrs, "cidr", "0.0.0.0/0,::/0", "允许 IP 段")
	flag.StringVar(&dnsServer, "dns", "119.29.29.29:53", "DNS 服务器")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH 查询域名")
	// 【核心修改】这里定义的是“单地址并发数”
	flag.IntVar(&connectionNum, "n", 7, "单地址并发通道数 (总通道数 = 地址数 * n)")
}

func main() {
	flag.Parse()

	// 解析服务端地址列表
	var forwardAddrs []string
	if forwardAddr != "" {
		parts := strings.Split(forwardAddr, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				forwardAddrs = append(forwardAddrs, trimmed)
			}
		}
	}

	if strings.HasPrefix(listenAddr, "ws://") || strings.HasPrefix(listenAddr, "wss://") {
		runWebSocketServer(listenAddr)
		return
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

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "closed network connection") || strings.Contains(s, "broken pipe") || strings.Contains(s, "reset by peer")
}

// ======================== ECH Logic ========================

const typeHTTPS = 65

func prepareECH() error {
	for {
		// log.Printf("查询 ECH: %s via %s", echDomain, dnsServer)
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
		if off+10 > len(b) {
			break
		}
		rtype := binary.BigEndian.Uint16(b[off : off+2])
		off += 8
		dlen := binary.BigEndian.Uint16(b[off : off+2])
		off += 2
		if off+int(dlen) > len(b) {
			break
		}
		if rtype == typeHTTPS {
			return parseHTTPSRecord(b[off : off+int(dlen)]), nil
		}
		off += int(dlen)
	}
	return "", nil
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

// ======================== ECH Pool (Super Racing Mode) ========================

type ECHPool struct {
	wsServerAddrs []string
	perAddrNum    int // 单个地址的并发数
	totalNum      int // 总并发数 = addrs * perAddrNum

	conns []*websocket.Conn
	locks []sync.Mutex

	tcpMap    sync.Map // id -> net.Conn
	chMap     sync.Map // id -> channelIndex (winner)
	connected sync.Map // id -> chan bool
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
	// 双重循环：遍历每个地址，为每个地址启动 n 条连接
	for _, addr := range p.wsServerAddrs {
		for i := 0; i < p.perAddrNum; i++ {
			go p.maintainConn(globalIdx, addr)
			globalIdx++
		}
	}
	log.Printf("[连接池] 启动完成。监控地址数: %d, 单地址通道: %d, 总通道数: %d", len(p.wsServerAddrs), p.perAddrNum, p.totalNum)
}

func (p *ECHPool) maintainConn(idx int, addr string) {
	for {
		ws, err := dialWebSocketWithECH(addr, 2)
		if err != nil {
			log.Printf("[通道-%d] 连接 %s 失败，2s后重试...", idx, addr)
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

	// 广播竞速：向所有（21条）通道同时发送 CLAIM
	// 任何一条通道（无论属于哪个地址）先回包，就用哪条
	for i := 0; i < p.totalNum; i++ {
		ws := p.conns[i]
		if ws == nil {
			continue
		}
		// 异步发送以避免阻塞
		go func(idx int, w *websocket.Conn) {
			p.locks[idx].Lock()
			w.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("CLAIM:%s|%d", connID, idx)))
			p.locks[idx].Unlock()
		}(i, ws)
	}

	p.chMap.Store(connID+"_META", fmt.Sprintf("%s|%s", target, first))
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
		return fmt.Errorf("ws closed")
	}
	err := ws.WriteMessage(websocket.TextMessage, []byte("DATA:"+connID+"|"+string(data)))
	p.locks[idx].Unlock()
	return err
}

func (p *ECHPool) SendClose(connID string) error {
	v, ok := p.chMap.Load(connID)
	if !ok {
		return nil
	}
	idx := v.(int)
	p.locks[idx].Lock()
	ws := p.conns[idx]
	if ws != nil {
		ws.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
	}
	p.locks[idx].Unlock()
	return nil
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
			err := ws.WriteMessage(websocket.PingMessage, nil)
			p.locks[idx].Unlock()
			if err != nil {
				return
			}
		}
	}()

	for {
		mt, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.BinaryMessage {
			if len(msg) > 9 && string(msg[:9]) == "UDP_DATA:" {
				// UDP logic omitted for brevity in TCP context
				continue
			}
			if len(msg) > 5 && string(msg[:5]) == "DATA:" {
				parts := strings.SplitN(string(msg[5:]), "|", 2)
				if len(parts) == 2 {
					if c, ok := p.tcpMap.Load(parts[0]); ok {
						c.(net.Conn).Write([]byte(parts[1]))
					}
				}
				continue
			}
		}
		if mt == websocket.TextMessage {
			s := string(msg)
			if strings.HasPrefix(s, "CLAIM_ACK:") {
				parts := strings.SplitN(s[10:], "|", 2)
				if len(parts) == 2 {
					connID := parts[0]
					// 只有第一个到达的 CLAIM_ACK 能写入 chMap，其他忽略
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
	echPool = NewECHPool(addrs, connectionNum)
	echPool.Start()

	parts := strings.Split(listen, "/")
	l, err := net.Listen("tcp", parts[0])
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("TCP 监听启动: %s -> %s", parts[0], parts[1])

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			id := uuid.New().String()
			p := make([]byte, 32768)
			// Read first packet to determine protocol/sni/etc if needed, or just data
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _ := c.Read(p)
			c.SetReadDeadline(time.Time{})

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
	log.Printf("代理启动: %s (服务器: %d 个, 单机并发: %d, 总通道: %d)",
		config.Host, len(addrs), connectionNum, len(addrs)*connectionNum)

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
				_, port, _ := net.SplitHostPort(addr)
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
	return nil, fmt.Errorf("failed to connect")
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

// SOCKS5/HTTP 简化版实现，保留核心转发逻辑
func handleSOCKS5(conn net.Conn, cfg *ProxyConfig) {
	// 简单握手: 忽略认证细节，直接接受
	conn.Write([]byte{0x05, 0x00})
	// 读请求
	buf := make([]byte, 262)
	io.ReadFull(conn, buf[:4])
	if buf[1] != 0x01 { // 只支持 CONNECT
		return
	}
	var target string
	switch buf[3] {
	case 1: // IPv4
		io.ReadFull(conn, buf[:4])
		target = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case 3: // Domain
		io.ReadFull(conn, buf[:1])
		l := int(buf[0])
		io.ReadFull(conn, buf[:l])
		target = string(buf[:l])
	}
	io.ReadFull(conn, buf[:2])
	target += fmt.Sprintf(":%d", int(buf[0])<<8|int(buf[1]))

	// 建立连接
	id := uuid.New().String()
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // 响应成功

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
	// 极简 HTTP 转发逻辑
	buf := bytes.NewBuffer([]byte{first})
	// 读取前面的部分以获取 Host
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
	
	var target string
	if method == "CONNECT" {
		target = urlStr
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		full = nil // CONNECT 不发送 header 给后端
	} else {
		u, _ := url.Parse(urlStr)
		target = u.Host
		if target == "" {
			// 尝试从 Host 头获取
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

// ======================== Server Stub (Not used in client mode) ========================
func runWebSocketServer(addr string) { log.Fatal("Server mode not optimized in this version") }
