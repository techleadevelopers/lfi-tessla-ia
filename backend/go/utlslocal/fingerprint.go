package utlslocal

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"
)

type FingerprintInfo struct {
	OS    string
	Stack string
}

func CriarClienteTLSFakeFingerprint() *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519, tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Transport: transport, Timeout: 15 * time.Second}
}

func PassiveFingerprint(url string) FingerprintInfo {
	client := CriarClienteTLSFakeFingerprint()
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return FingerprintInfo{"unknown", "unknown"}
	}
	resp, err := client.Do(req)
	if err != nil {
		return FingerprintInfo{"unknown", "unknown"}
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	os := "unix"
	if strings.Contains(strings.ToLower(server), "windows") {
		os = "windows"
	}
	stack := "php"
	if strings.Contains(strings.ToLower(server), "asp") {
		stack = "asp.net"
	}
	return FingerprintInfo{OS: os, Stack: stack}
}

func ActiveFingerprint(url string) FingerprintInfo {
	fp := PassiveFingerprint(url)
	testURL := url + "../../etc/passwd"
	client := &http.Client{Timeout: 7 * time.Second}
	req, _ := http.NewRequest("GET", testURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return fp
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		fp.Stack = "waf-protected"
	}
	return fp
}
