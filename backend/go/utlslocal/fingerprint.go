// utlslocal/utlslocal.go
package utlslocal

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/salesforce/ja3"
)

//---------------//
// Config & Utils
//---------------//

// Listas de HelloIDs suportados
var helloIDs = []utls.HelloID{
	utls.HelloChrome_110,
	utls.HelloFirefox_102,
	utls.HelloRandomizedNoALPN,
	utls.HelloIOS_13_0,
}

// Alguns conjuntos de SignatureSchemes
var sigSchemesList = [][]utls.SignatureScheme{
	{utls.ECDSAWithP256AndSHA256},
	{utls.PSSWithSHA256, utls.ECDSAWithP256AndSHA256},
}

// ALPNs possíveis
var alpnList = [][]string{
	{"h2", "http/1.1"},
	{"http/1.1"},
	{"spdy/3", "http/1.1"},
}

// Fake CDNs para SNI spoofing
var fakeCDNs = []string{
	"www.cloudflare.com",
	"www.akamai.net",
	"edgekey.net",
}

// randomChoice genérico
func randomChoice[T any](arr []T) T {
	return arr[mrand.Intn(len(arr))]
}

// randomDomainGibberish
func randomDomain() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	n := mrand.Intn(8) + 5
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	return string(b) + ".com"
}

//---------------//
// Core: uTLS Client
//---------------//

// UTLSConfig armazena parâmetros para o ClientHello spoofado
type UTLSConfig struct {
	HelloID          utls.HelloID
	SignatureSchemes []utls.SignatureScheme
	NextProtos       []string
	ServerName       string
	UseFakeCDN       bool
}

// NewRandomUTLSConfig retorna uma configuração aleatória
func NewRandomUTLSConfig(targetHost string) *UTLSConfig {
	h := randomChoice(helloIDs)
	sigs := randomChoice(sigSchemesList)
	alpn := randomChoice(alpnList)
	sni := targetHost
	useFake := mrand.Intn(2) == 0
	if useFake {
		sni = randomChoice(fakeCDNs)
	}
	return &UTLSConfig{
		HelloID:          h,
		SignatureSchemes: sigs,
		NextProtos:       alpn,
		ServerName:       sni,
		UseFakeCDN:       useFake,
	}
}

// DialUTLS estabelece um handshake via utls com o ClientHello modificado
func (c *UTLSConfig) DialUTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	// Respeita proxy HTTP(S)_PROXY se definido
	proxyURL, _ := http.ProxyFromEnvironment(&http.Request{URL: mustParseURL("https://" + addr)})
	var dialer net.Dialer
	if proxyURL != nil {
		return dialer.DialContext(ctx, "tcp", proxyURL.Host)
	}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         c.ServerName,
		NextProtos:         c.NextProtos,
		SignatureSchemes:   make([]tls.SignatureScheme, len(c.SignatureSchemes)),
	}
	for i, s := range c.SignatureSchemes {
		config.SignatureSchemes[i] = tls.SignatureScheme(s)
	}

	uc := utls.UClient(rawConn, config, c.HelloID)
	if err := uc.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	return uc, nil
}

// NewHTTPClient cria um *http.Client que usa utls spoofado
func NewHTTPClient(targetHost string) *http.Client {
	cfg := NewRandomUTLSConfig(targetHost)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cfg.DialUTLS(ctx, network, addr)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
}

//---------------//
// HTTP Header-Order Spoofing
//---------------//

// HeaderPair preserva ordem
type HeaderPair struct {
	Key, Value string
}

// SpoofTransport escreve headers na ordem especificada
type SpoofTransport struct {
	Base   http.RoundTripper
	Header []HeaderPair
}

func (st *SpoofTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	conn, err := st.dialRaw(req)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, _ = conn.Write([]byte(req.Method + " " + req.URL.RequestURI() + " HTTP/1.1\r\n"))
	for _, hv := range st.Header {
		_, _ = conn.Write([]byte(hv.Key + ": " + hv.Value + "\r\n"))
	}
	_, _ = conn.Write([]byte("\r\n"))

	br := bufio.NewReader(conn)
	return http.ReadResponse(br, req)
}

func (st *SpoofTransport) dialRaw(req *http.Request) (net.Conn, error) {
	if transport, ok := st.Base.(*http.Transport); ok && transport.DialContext != nil {
		return transport.DialContext(req.Context(), "tcp", req.URL.Host)
	}
	return nil, errors.New("base transport não suporta DialContext")
}

//---------------//
// Fingerprinting & Evasão
//---------------//

type FingerprintInfo struct{ OS, Stack string }

// PassiveFingerprint — igual antes, mas usando NewHTTPClient
func PassiveFingerprint(url string) FingerprintInfo {
	client := NewHTTPClient(extractHost(url))
	req, _ := http.NewRequest("HEAD", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return FingerprintInfo{"unknown", "unknown"}
	}
	defer resp.Body.Close()

	srv := strings.ToLower(resp.Header.Get("Server"))
	os := "unix"
	if strings.Contains(srv, "windows") {
		os = "windows"
	}
	stack := "php"
	if strings.Contains(srv, "asp") {
		stack = "asp.net"
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("X-Frame-Options")), "deny") {
		stack = "waf-locked"
	}
	return FingerprintInfo{OS: os, Stack: stack}
}

// ActiveFingerprint — idem, com testes de contenção
func ActiveFingerprint(url string) FingerprintInfo {
	fp := PassiveFingerprint(url)
	client := NewHTTPClient(extractHost(url))
	testPaths := []string{"../../etc/passwd", "/proc/self/environ", "/index.php?page="}
	for _, p := range testPaths {
		resp, err := client.Get(url + p)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == 403 {
			fp.Stack = "waf-protected"
		}
	}
	if strings.Contains(fp.Stack, "waf") {
		fp.Stack = "waf-detected"
	}
	return fp
}

// FingerprintTLS retorna versão TLS + JA3 spoof fingerprint de client
func FingerprintTLS(url string) FingerprintInfo {
	client := NewHTTPClient(extractHost(url))
	req, _ := http.NewRequest("HEAD", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return FingerprintInfo{"unknown", "unknown"}
	}
	defer resp.Body.Close()

	state := resp.TLS
	if state == nil {
		return FingerprintInfo{"unknown", "unknown"}
	}
	version := "TLS1.2"
	if state.Version == tls.VersionTLS13 {
		version = "TLS1.3"
	}
	cs := state.CipherSuite
	return FingerprintInfo{"unknown", version + " 0x" + strings.ToUpper(hexUint16(cs))}
}

// EvasaoWAFs roda técnicas de evasão
func EvasaoWAFs(url string) {
	log.Println("🚀 Iniciando evasão de WAFs...")

	client := NewHTTPClient(extractHost(url))
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", randomUA())
	headerOrder := []HeaderPair{
		{"Host", extractHost(url)},
		{"User-Agent", req.Header.Get("User-Agent")},
		{"Accept", "*/*"},
	}
	client.Transport = &SpoofTransport{Base: client.Transport, Header: headerOrder}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Erro: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 {
		log.Println("🚫 WAF detectado!")
	}
}

//---------------//
// Helpers finais
//---------------//

func extractHost(rawurl string) string {
	u, err := http.ParseRequestURI(rawurl)
	if err != nil {
		return rawurl
	}
	return u.Host
}

func randomUA() string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
}

func hexUint16(v uint16) string {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return string([]byte{hex[b[0]>>4], hex[b[0]&0xF], hex[b[1]>>4], hex[b[1]&0xF]})
}

var hex = []byte("0123456789ABCDEF")

func mustParseURL(u string) *http.URL {
	parsed, _ := http.ParseRequestURI(u)
	return parsed
}

// logToFile continua o mesmo
func logToFile(message string) {
	f, err := os.OpenFile("error_log.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("❌ %v", err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(time.Now().Format(time.RFC3339) + " " + message + "\n")
}

//------------------------------//
// 🧠 SUGESTÕES DE EXTENSÃO – DEEP LEVEL
//------------------------------//

// 1. ClientHelloSpec + Fragmentação real
func FragmentedClientHelloDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	spec := utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: "cloudflare.com"},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
	uc := utls.UClient(rawConn, &tls.Config{InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uc.ApplyPreset(&spec); err != nil {
		return nil, err
	}
	if err := uc.Handshake(); err != nil {
		return nil, err
	}
	return uc, nil
}

// 2. Renegociação Controlada
func RenegotiateConn(uconn *utls.UConn) error {
	if err := uconn.Renegotiate(); err != nil {
		return err
	}
	return nil
}

// 3. Interleaving de TLS Records
type InterleavedConn struct {
	net.Conn
	fragmentSizes []int
}

func (ic *InterleavedConn) Write(p []byte) (n int, err error) {
	offset := 0
	for _, size := range ic.fragmentSizes {
		if offset+size > len(p) {
			size = len(p) - offset
		}
		if size <= 0 {
			break
		}
		ic.Conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		w, e := ic.Conn.Write(p[offset : offset+size])
		n += w
		offset += size
		if e != nil {
			return n, e
		}
		time.Sleep(50 * time.Millisecond) // jitter
	}
	return n, nil
}

// 4. Proxy-aware uTLS já integrado em DialUTLS (usa http.ProxyFromEnvironment)

// 5. JA3 fingerprint real
func LogJA3Fingerprint(uconn *utls.UConn) {
	cs := uconn.GetClientHelloMsg().CipherSuites
	exts := uconn.GetClientHelloMsg().Extensions
	curves := uconn.GetClientHelloMsg().SupportedCurves
	pointFmt := uconn.GetClientHelloMsg().SupportedPoints
	j := ja3.NewJAF3(cs, exts, curves, pointFmt)
	hash := j.Hash()
	logToFile("JA3: " + hash)
}

// 6. Gerador de Fingerprint baseado em ML (future dream)
// – você pode, em cada resposta, chamar logToFile com:
// Host, SNI, HelloID, ALPN, StatusCode, Latency, JA3Hash
// e depois treinar offline um modelo para escolher o melhor UTLSConfig.