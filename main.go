package main

import (
	"bytes"
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
	connectionNum int

	dnsServer string
	echDomain string

	echListMu sync.RWMutex
	echList   []byte

	echPool *ECHPool
)

func init() {
	flag.StringVar(&listenAddr, "l", "", "Listen Address")
	flag.StringVar(&forwardAddr, "f", "", "Forward Address")
	flag.StringVar(&ipAddr, "ip", "", "Specific IP")
	flag.StringVar(&certFile, "cert", "", "Cert File")
	flag.StringVar(&keyFile, "key", "", "Key File")
	flag.StringVar(&token, "token", "", "Token")
	flag.StringVar(&dnsServer, "dns", "119.29.29.29:53", "DNS")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH Domain")
	flag.IntVar(&connectionNum, "n", 3, "Concurrency")
	
	// 兼容参数
	var dummy string
	flag.StringVar(&dummy, "cidr", "", "ignored")
}

func main() {
	flag.Parse()

	if strings.HasPrefix(listenAddr, "ws://") || strings.HasPrefix(listenAddr, "wss://") {
		runWebSocketServer(listenAddr)
		return
	}
	if strings.HasPrefix(listenAddr, "tcp://") {
		if err := prepareECH(); err != nil {
			log.Fatalf("ECH Fail: %v", err)
		}
		runTCPClient(listenAddr, forwardAddr)
		return
	}
	if strings.HasPrefix(listenAddr, "proxy://") {
		if err := prepareECH(); err != nil {
			log.Fatalf("ECH Fail: %v", err)
		}
		runProxyServer(listenAddr, forwardAddr)
		return
	}
	log.Fatal("Invalid address format")
}

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "closed") || strings.Contains(s, "broken pipe") || strings.Contains(s, "reset")
}

// ======================== ECH Logic ========================

const typeHTTPS = 65

func prepareECH() error {
	for {
		log.Printf("Fetching ECH from %s via %s", echDomain, dnsServer)
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
		log.Printf("ECH Config Loaded")
		return nil
	}
}

func refreshECH() {
	prepareECH()
}

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("ECH not loaded")
	}
	return echList, nil
}

func buildTLSConfigWithECH(sn string, el []byte) (*tls.Config, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
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

// ======================== Server ========================

func generateSelfSignedCert() (tls.Certificate, error) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"Self"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	b, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &k.PublicKey, k)
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
	kp := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return tls.X509KeyPair(cp, kp)
}

func runWebSocketServer(addr string) {
	u, _ := url.Parse(addr)
	path := u.Path
	if path == "" {
		path = "/"
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
		Subprotocols: func() []string {
			if token != "" {
				return []string{token}
			}
			return nil
		}(),
		ReadBufferSize: 65536, WriteBufferSize: 65536,
	}
	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if token != "" && r.Header.Get("Sec-WebSocket-Protocol") != token {
			http.Error(w, "Unauthorized", 401)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		go handleWebSocket(ws)
	})
	if u.Scheme == "wss" {
		s := &http.Server{Addr: u.Host}
		if certFile != "" {
			s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			log.Fatal(s.ListenAndServeTLS(certFile, keyFile))
		} else {
			c, _ := generateSelfSignedCert()
			s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13}
			log.Fatal(s.ListenAndServeTLS("", ""))
		}
	} else {
		log.Fatal(http.ListenAndServe(u.Host, nil))
	}
}

func handleWebSocket(ws *websocket.Conn) {
	var mu sync.Mutex
	var connMu sync.RWMutex
	conns := make(map[string]net.Conn)
	ws.SetPingHandler(func(d string) error {
		mu.Lock()
		defer mu.Unlock()
		return ws.WriteMessage(websocket.PongMessage, []byte(d))
	})
	
	defer func() {
		connMu.Lock()
		for _, c := range conns { c.Close() }
		connMu.Unlock()
		ws.Close()
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
					connMu.RLock()
					c, ok := conns[parts[0]]
					connMu.RUnlock()
					if ok {
						c.Write([]byte(parts[1]))
					}
				}
			}
			continue
		}
		if mt == websocket.TextMessage {
			s := string(msg)
			if strings.HasPrefix(s, "TCP:") {
				parts := strings.SplitN(s[4:], "|", 3)
				if len(parts) >= 2 {
					id, tgt := parts[0], parts[1]
					first := ""
					if len(parts) == 3 {
						first = parts[2]
					}
					go handleTCPConn(ws, &mu, &connMu, conns, id, tgt, first)
				}
			} else if strings.HasPrefix(s, "CLOSE:") {
				id := strings.TrimPrefix(s, "CLOSE:")
				connMu.Lock()
				if c, ok := conns[id]; ok {
					c.Close()
					delete(conns, id)
				}
				connMu.Unlock()
			}
		}
	}
}

func handleTCPConn(ws *websocket.Conn, mu *sync.Mutex, connMu *sync.RWMutex, conns map[string]net.Conn, id, tgt, first string) {
	c, err := net.DialTimeout("tcp", tgt, 10*time.Second)
	if err != nil {
		mu.Lock()
		ws.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+id))
		mu.Unlock()
		return
	}
	connMu.Lock()
	conns[id] = c
	connMu.Unlock()
	defer func() {
		c.Close()
		connMu.Lock()
		delete(conns, id)
		connMu.Unlock()
	}()
	if first != "" {
		c.Write([]byte(first))
	}
	mu.Lock()
	ws.WriteMessage(websocket.TextMessage, []byte("CONNECTED:"+id))
	mu.Unlock()
	buf := make([]byte, 32768)
	for {
		n, err := c.Read(buf)
		if err != nil {
			mu.Lock()
			ws.WriteMessage(websocket.TextMessage, []byte("CLOSE:"+id))
			mu.Unlock()
			return
		}
		mu.Lock()
		ws.WriteMessage(websocket.BinaryMessage, append([]byte("DATA:"+id+"|"), buf[:n]...))
		mu.Unlock()
	}
}

// ======================== Client Pool ========================

type ECHPool struct {
	wsAddr string
	n      int
	conns  []*websocket.Conn
	locks  []sync.Mutex
	rr     int
	mu     sync.Mutex
	tcpMap sync.Map
}

func NewECHPool(addr string, n int) *ECHPool {
	return &ECHPool{
		wsAddr: addr, n: n,
		conns: make([]*websocket.Conn, n),
		locks: make([]sync.Mutex, n),
	}
}

func (p *ECHPool) Start() {
	for i := 0; i < p.n; i++ {
		go p.dial(i)
	}
}

func (p *ECHPool) dial(idx int) {
	for {
		ws, err := dialWebSocketWithECH(p.wsAddr, 2)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("Channel %d connected", idx)
		p.conns[idx] = ws
		p.handle(idx, ws)
		time.Sleep(1 * time.Second)
	}
}

func (p *ECHPool) handle(idx int, ws *websocket.Conn) {
	ws.SetPingHandler(func(d string) error {
		p.locks[idx].Lock()
		defer p.locks[idx].Unlock()
		return ws.WriteMessage(websocket.PongMessage, []byte(d))
	})
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
		} else if mt == websocket.TextMessage {
			s := string(msg)
			if strings.HasPrefix(s, "CLOSE:") {
				id := strings.TrimPrefix(s, "CLOSE:")
				if c, ok := p.tcpMap.Load(id); ok {
					c.(net.Conn).Close()
					p.tcpMap.Delete(id)
				}
			}
		}
	}
}

func (p *ECHPool) Send(connID, target, first string, conn net.Conn) {
	p.tcpMap.Store(connID, conn)
	p.mu.Lock()
	idx := p.rr
	p.rr = (p.rr + 1) % p.n
	p.mu.Unlock()

	p.locks[idx].Lock()
	ws := p.conns[idx]
	if ws == nil {
		p.locks[idx].Unlock()
		conn.Close()
		return
	}
	ws.WriteMessage(websocket.TextMessage, []byte("TCP:"+connID+"|"+target+"|"+first))
	p.locks[idx].Unlock()

	defer func() {
		p.locks[idx].Lock()
		if p.conns[idx] != nil {
			p.conns[idx].WriteMessage(websocket.TextMessage, []byte("CLOSE:"+connID))
		}
		p.locks[idx].Unlock()
		p.tcpMap.Delete(connID)
		conn.Close()
	}()

	buf := make([]byte, 32768)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		p.locks[idx].Lock()
		if p.conns[idx] == nil {
			p.locks[idx].Unlock()
			return
		}
		err = p.conns[idx].WriteMessage(websocket.BinaryMessage, append([]byte("DATA:"+connID+"|"), buf[:n]...))
		p.locks[idx].Unlock()
		if err != nil {
			return
		}
	}
}

// ======================== Client Entry ========================

func runTCPClient(listen, server string) {
	listen = strings.TrimPrefix(listen, "tcp://")
	parts := strings.Split(listen, "/")
	if len(parts) < 2 {
		log.Fatal("invalid listen addr")
	}
	echPool = NewECHPool(server, connectionNum)
	echPool.Start()
	l, _ := net.Listen("tcp", parts[0])
	log.Printf("TCP Start: %s -> %s", parts[0], parts[1])
	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			id := uuid.New().String()
			buf := make([]byte, 32768)
			n, _ := c.Read(buf)
			echPool.Send(id, parts[1], string(buf[:n]), c)
		}()
	}
}

func runProxyServer(addr, server string) {
	c, _ := parseProxyAddr(addr)
	l, _ := net.Listen("tcp", c.Host)
	log.Printf("Proxy Start: %s", c.Host)
	echPool = NewECHPool(server, connectionNum)
	echPool.Start()
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go handleProxy(conn, c)
	}
}

func dialWebSocketWithECH(wsAddr string, retries int) (*websocket.Conn, error) {
	u, _ := url.Parse(wsAddr)
	if u.Scheme != "wss" {
		return nil, fmt.Errorf("must use wss")
	}
	dialer := websocket.Dialer{
		Subprotocols:     []string{token},
		HandshakeTimeout: 5 * time.Second,
	}
	if ipAddr != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(a)
			return net.DialTimeout(n, net.JoinHostPort(ipAddr, p), 5*time.Second)
		}
	}
	sn := u.Hostname()
	for i := 0; i <= retries; i++ {
		el, err := getECHList()
		if err != nil {
			refreshECH()
			continue
		}
		cfg, _ := buildTLSConfigWithECH(sn, el)
		dialer.TLSClientConfig = cfg
		ws, _, err := dialer.Dial(wsAddr, nil)
		if err != nil {
			if strings.Contains(err.Error(), "ECH") {
				refreshECH()
			}
			continue
		}
		return ws, nil
	}
	return nil, fmt.Errorf("fail")
}

// ======================== Proxy ========================

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

func handleProxy(conn net.Conn, cfg *ProxyConfig) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	if b[0] == 0x05 {
		conn.Write([]byte{0x05, 0x00})
		h := make([]byte, 4)
		io.ReadFull(conn, h)
		if h[1] != 0x01 {
			conn.Close()
			return
		}
		var tgt string
		switch h[3] {
		case 1:
			b := make([]byte, 4)
			io.ReadFull(conn, b)
			tgt = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
		case 3:
			b := make([]byte, 1)
			io.ReadFull(conn, b)
			d := make([]byte, int(b[0]))
			io.ReadFull(conn, d)
			tgt = string(d)
		}
		pb := make([]byte, 2)
		io.ReadFull(conn, pb)
		tgt += fmt.Sprintf(":%d", int(pb[0])<<8|int(pb[1]))
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		echPool.Send(uuid.New().String(), tgt, "", conn)
	} else {
		// Simple HTTP
		buf := bytes.NewBuffer(b)
		p := make([]byte, 4096)
		n, _ := conn.Read(p)
		full := append(buf.Bytes(), p[:n]...)
		lines := strings.Split(string(full), "\r\n")
		parts := strings.Split(lines[0], " ")
		if len(parts) < 2 {
			conn.Close()
			return
		}
		var tgt string
		if parts[0] == "CONNECT" {
			tgt = parts[1]
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			full = nil
		} else {
			u, _ := url.Parse(parts[1])
			tgt = u.Host
			if tgt == "" {
				for _, l := range lines {
					if strings.HasPrefix(l, "Host:") {
						tgt = strings.TrimSpace(strings.TrimPrefix(l, "Host:"))
						break
					}
				}
			}
			if !strings.Contains(tgt, ":") {
				tgt += ":80"
			}
		}
		echPool.Send(uuid.New().String(), tgt, string(full), conn)
	}
}
