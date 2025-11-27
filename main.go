package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== 全局参数 ========================

var (
	listenAddr   string
	forwardAddrs []string
	ipAddr       string
	token        string
	raceCount    int

	dnsServer string
	echDomain string

	echListMu sync.RWMutex
	echList   []byte
)

func init() {
	var fwd string
	flag.StringVar(&listenAddr, "l", "", "Listen")
	flag.StringVar(&fwd, "f", "", "Forward")
	flag.StringVar(&ipAddr, "ip", "", "IP")
	flag.StringVar(&token, "token", "", "Token")
	flag.StringVar(&dnsServer, "dns", "119.29.29.29:53", "DNS")
	flag.StringVar(&echDomain, "ech", "cloudflare-ech.com", "ECH")
	flag.IntVar(&raceCount, "n", 3, "N")

	// 兼容性占位
	var dummy string
	flag.StringVar(&dummy, "cert", "", "ignored")
	flag.StringVar(&dummy, "key", "", "ignored")
	flag.StringVar(&dummy, "cidr", "", "ignored")

	flag.Parse()

	if fwd != "" {
		parts := strings.Split(fwd, ",")
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				forwardAddrs = append(forwardAddrs, t)
			}
		}
	}
}

func main() {
	// 彻底移除服务端模式支持，避免引入 net/http 导致未使用的错误
	if strings.HasPrefix(listenAddr, "ws://") || strings.HasPrefix(listenAddr, "wss://") {
		log.Fatal("Server mode not supported in this binary")
	}

	if len(forwardAddrs) == 0 {
		log.Fatal("Missing -f")
	}

	if err := prepareECH(); err != nil {
		log.Fatalf("ECH Fail: %v", err)
	}

	if strings.HasPrefix(listenAddr, "tcp://") {
		runTCPClient(listenAddr)
	} else if strings.HasPrefix(listenAddr, "proxy://") {
		runProxyServer(listenAddr)
	} else {
		log.Fatal("Invalid addr (use tcp:// or proxy://)")
	}
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

func refreshECH() { prepareECH() }

func getECHList() ([]byte, error) {
	echListMu.RLock()
	defer echListMu.RUnlock()
	if len(echList) == 0 {
		return nil, errors.New("No ECH")
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

// ======================== Racing Logic ========================

func raceDialAndPipe(conn net.Conn, target string, firstData string) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resultCh := make(chan *websocket.Conn, raceCount)

	for i := 0; i < raceCount; i++ {
		// 使用 math/rand，避免与 crypto/rand 冲突
		addr := forwardAddrs[rand.Intn(len(forwardAddrs))]
		go func(workerAddr string) {
			ws, err := dialAndHandshake(ctx, workerAddr, target, firstData)
			if err == nil {
				select {
				case resultCh <- ws:
				case <-ctx.Done():
					ws.Close()
				}
			}
		}(addr)
	}

	var ws *websocket.Conn
	select {
	case ws = <-resultCh:
		cancel()
	case <-time.After(10 * time.Second):
		return
	}
	defer ws.Close()
	pipe(conn, ws)
}

func dialAndHandshake(ctx context.Context, wsAddr string, target, firstData string) (*websocket.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ws, err := dialWebSocketWithECH(wsAddr)
	if err != nil {
		return nil, err
	}

	cmd := fmt.Sprintf("CONNECT:%s|%s", target, firstData)
	if err := ws.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
		ws.Close()
		return nil, err
	}

	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg, err := ws.ReadMessage()
	ws.SetReadDeadline(time.Time{})

	if err != nil {
		ws.Close()
		return nil, err
	}
	if string(msg) != "CONNECTED" {
		ws.Close()
		return nil, fmt.Errorf("refused")
	}
	return ws, nil
}

func dialWebSocketWithECH(wsAddr string) (*websocket.Conn, error) {
	u, _ := url.Parse(wsAddr)
	dialer := websocket.Dialer{HandshakeTimeout: 4 * time.Second}
	if token != "" {
		dialer.Subprotocols = []string{token}
	}

	if ipAddr != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) {
			return net.DialTimeout(n, net.JoinHostPort(ipAddr, "443"), 4*time.Second)
		}
	}

	el, err := getECHList()
	if err != nil {
		refreshECH()
		return nil, err
	}

	cfg, _ := buildTLSConfigWithECH(u.Hostname(), el)
	dialer.TLSClientConfig = cfg

	ws, _, err := dialer.Dial(wsAddr, nil)
	return ws, err
}

func pipe(conn net.Conn, ws *websocket.Conn) {
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					errCh <- werr
					return
				}
			}
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			if len(data) > 0 {
				if _, werr := conn.Write(data); werr != nil {
					errCh <- werr
					return
				}
			}
		}
	}()
	<-errCh
}

// ======================== Entry Points ========================

func runTCPClient(listen string) {
	listen = strings.TrimPrefix(listen, "tcp://")
	parts := strings.Split(listen, "/")
	if len(parts) < 2 {
		log.Fatal("tcp://listen/target")
	}

	l, err := net.Listen("tcp", parts[0])
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("TCP Listen: %s -> %s (Race: %d)", parts[0], parts[1], raceCount)

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			buf := make([]byte, 4096)
			c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _ := c.Read(buf)
			c.SetReadDeadline(time.Time{})
			raceDialAndPipe(c, parts[1], string(buf[:n]))
		}()
	}
}

func runProxyServer(addr string) {
	c, _ := parseProxyAddr(addr)
	l, err := net.Listen("tcp", c.Host)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Proxy Listen: %s (Race: %d)", c.Host, raceCount)

	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go handleProxy(conn, c)
	}
}

// ======================== Proxy Parser ========================

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
func validateAuth(h, u, p string) bool {
	if h == "" || !strings.HasPrefix(h, "Basic ") {
		return false
	}
	d, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	pts := strings.SplitN(string(d), ":", 2)
	return len(pts) == 2 && pts[0] == u && pts[1] == p
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
		var tgt string
		switch h[3] {
		case 1:
			buf := make([]byte, 4)
			io.ReadFull(conn, buf)
			tgt = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		case 3:
			buf := make([]byte, 1)
			io.ReadFull(conn, buf)
			d := make([]byte, int(buf[0]))
			io.ReadFull(conn, d)
			tgt = string(d)
		}
		p := make([]byte, 2)
		io.ReadFull(conn, p)
		tgt += fmt.Sprintf(":%d", int(p[0])<<8|int(p[1]))

		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		raceDialAndPipe(conn, tgt, "")
	} else {
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		full := append(b, buf[:n]...)
		str := string(full)
		lines := strings.Split(str, "\r\n")
		parts := strings.Split(lines[0], " ")
		if len(parts) < 2 {
			conn.Close()
			return
		}

		if cfg.Username != "" {
			auth := ""
			for _, l := range lines {
				if strings.HasPrefix(l, "Proxy-Authorization:") {
					auth = strings.TrimSpace(strings.TrimPrefix(l, "Proxy-Authorization:"))
				}
			}
			if !validateAuth(auth, cfg.Username, cfg.Password) {
				conn.Write([]byte("HTTP/1.1 407 Auth Required\r\n\r\n"))
				conn.Close()
				return
			}
		}

		if parts[0] == "CONNECT" {
			conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
			raceDialAndPipe(conn, parts[1], "")
		} else {
			u, _ := url.Parse(parts[1])
			tgt := u.Host
			if tgt == "" {
				for _, l := range lines {
					if strings.HasPrefix(l, "Host:") {
						tgt = strings.TrimSpace(strings.TrimPrefix(l, "Host:"))
					}
				}
			}
			if !strings.Contains(tgt, ":") {
				tgt += ":80"
			}
			raceDialAndPipe(conn, tgt, str)
		}
	}
}
