package proxy

import (
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"lfitessla/config"
)

type Proxy struct {
	Address  string
	Failures int
}

var (
	proxyList  []Proxy
	proxyMutex sync.Mutex
)

func init() {
	for _, addr := range config.ProxyList {
		proxyList = append(proxyList, Proxy{Address: addr})
	}
}

// Seleciona proxy com menos falhas
func SelecionarProxy() *Proxy {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()
	var candidatos []Proxy
	for _, p := range proxyList {
		if p.Failures < 3 {
			candidatos = append(candidatos, p)
		}
	}
	if len(candidatos) == 0 {
		return &proxyList[0]
	}
	return &candidatos[rand.Intn(len(candidatos))]
}

func SelecionarOutroProxy(atual *Proxy) *Proxy {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()
	var candidatos []Proxy
	for _, p := range proxyList {
		if atual == nil || p.Address != atual.Address && p.Failures < 3 {
			candidatos = append(candidatos, p)
		}
	}
	if len(candidatos) == 0 {
		return &proxyList[0]
	}
	return &candidatos[rand.Intn(len(candidatos))]
}

func MarcarFalha(p *Proxy) {
	proxyMutex.Lock()
	defer proxyMutex.Unlock()
	for i := range proxyList {
		if proxyList[i].Address == p.Address {
			proxyList[i].Failures++
		}
	}
}

func CriarClienteComProxy(proxyAddr string) (*http.Client, error) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		IdleConnTimeout:     10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
	return client, nil
}
