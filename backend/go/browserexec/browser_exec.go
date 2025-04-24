package browserexec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/burp-suite/burp-api-go"
)

// Struct para o request que será enviado ao microserviço de Puppeteer
type BrowserRequest struct {
	URL     string `json:"url"`
	Payload string `json:"payload"`
}

// Struct para a resposta do microserviço de Puppeteer
type BrowserResponse struct {
	Success bool   `json:"success"`
	Body    string `json:"body"`
}

// 🔌 Modo remoto: envia para microserviço Puppeteer stealth via HTTP
func ExecutarNoBrowser(url, payload string) (BrowserResponse, error) {
	data := BrowserRequest{URL: url, Payload: payload}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return BrowserResponse{}, fmt.Errorf("erro ao marshalling request: %v", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post("http://127.0.0.1:7777/execute", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return BrowserResponse{}, fmt.Errorf("erro ao enviar request para o microserviço: %v", err)
	}
	defer resp.Body.Close()

	var response BrowserResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return BrowserResponse{}, fmt.Errorf("erro ao decodificar resposta do microserviço: %v", err)
	}

	return response, nil
}

// 🧪 Modo local: executa Node+Puppeteer inline com stealth e coleta avançada
func HeadlessPayloadExec(targetURL string, payload string) error {
	// Proteção contra payload injection em fmt.Sprintf
	escapedPayload, _ := json.Marshal(payload)

	// Configuração do Puppeteer
	puppeteerConfig := fmt.Sprintf(`
		const puppeteer = require('puppeteer-extra');
		const StealthPlugin = require('puppeteer-extra-plugin-stealth');
		const fs = require('fs');

		puppeteer.use(StealthPlugin());

		(async () => {
			const browser = await puppeteer.launch({
				headless: true,
				args: [
					'--no-sandbox',
					'--disable-setuid-sandbox',
					'--disable-web-security',
					'--disable-features=IsolateOrigins,site-per-process',
					'--user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"'
				]
			});

			const page = await browser.newPage();
			await page.setExtraHTTPHeaders({
				'Accept-Language': 'en-US,en;q=0.9',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
			});

			await page.goto('%s', { waitUntil: 'networkidle2', timeout: 60000 });

			await page.evaluate(() => {
				let el = document.createElement('script');
				el.innerHTML = JSON.parse('%s');
				document.body.appendChild(el);
			}, targetURL, escapedPayload);

			const domDump = await page.content();
			const cookies = await page.cookies();
			const screenshot = await page.screenshot({ encoding: 'binary' });

			fs.writeFileSync('dom_result.html', domDump);
			fs.writeFileSync('cookies.json', JSON.stringify(cookies, null, 2));
			fs.writeFileSync('screenshot.png', screenshot);

			await browser.close();
		})();
	`)

	// Execução do Node.js
	cmd := exec.Command("node", "-e", puppeteerConfig)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("erro ao iniciar browser: %v", err)
	}

	done := make(chan error)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("⏱️ Timeout: processo foi interrompido após 60 segundos")
	case err := <-done:
		if err != nil {
			return fmt.Errorf("erro ao executar o browser: %v\nOutput: %s", err, out.String())
		}
	}

	return nil
}

// 🧪 Modo local: executa Node+Puppeteer inline com stealth e coleta avançada (com logs)
func HeadlessPayloadExecWithLogs(targetURL string, payload string) error {
	// Proteção contra payload injection em fmt.Sprintf
	escapedPayload, _ := json.Marshal(payload)

	// Configuração do Puppeteer
	puppeteerConfig := fmt.Sprintf(`
		const puppeteer = require('puppeteer-extra');
		const StealthPlugin = require('puppeteer-extra-plugin-stealth');
		const fs = require('fs');

		puppeteer.use(StealthPlugin());

		(async () => {
			console.log('Iniciando navegador...');
			const browser = await puppeteer.launch({
				headless: true,
				args: [
					'--no-sandbox',
					'--disable-setuid-sandbox',
					'--disable-web-security',
					'--disable-features=IsolateOrigins,site-per-process',
					'--user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"'
				]
			});

			console.log('Navegador iniciado. Acessando página...');
			const page = await browser.newPage();
			await page.setExtraHTTPHeaders({
				'Accept-Language': 'en-US,en;q=0.9',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
			});

			await page.goto('%s', { waitUntil: 'networkidle2', timeout: 60000 });

			console.log('Página acessada. Executando script...');
			await page.evaluate(() => {
				let el = document.createElement('script');
				el.innerHTML = JSON.parse('%s');
				document.body.appendChild(el);
			}, targetURL, escapedPayload);

			console.log('Script executado. Coletando dados...');
			const domDump = await page.content();
			const cookies = await page.cookies();
			const screenshot = await page.screenshot({ encoding: 'binary' });

			fs.writeFileSync('dom_result.html', domDump);
			fs.writeFileSync('cookies.json', JSON.stringify(cookies, null, 2));
			fs.writeFileSync('screenshot.png', screenshot);

			console.log('Dados coletados. Fechando navegador...');
			await browser.close();
		})();
	`)

	// Execução do Node.js
	cmd := exec.Command("node", "-e", puppeteerConfig)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("erro ao iniciar browser: %v", err)
	}

	done := make(chan error)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("⏱️ Timeout: processo foi interrompido após 60 segundos")
	case err := <-done:
		if err != nil {
			return fmt.Errorf("erro ao executar o browser: %v\nOutput: %s", err, out.String())
		}
	}

	return nil
}

// Integração com Burp
func IntegracaoBurp(url, payload string) error {
	burpAPI, err := burp.NewBurpAPI("http://localhost:8080")
	if err != nil {
		return fmt.Errorf("erro ao inicializar API do Burp: %v", err)
	}

	proxy := burpAPI.NewProxy()

	config := ExecConfig{
		URL:              url,
		Payload:          payload,
		Proxy:            proxy,
		CollectHAR:       true,
		CollectScreenshot: true,
		Verbose:          true,
		Headless:         true,
		OutputPath:       "./output",
	}

	if err := ExecuteBrowserAutomation(config); err != nil {
		return fmt.Errorf("erro ao executar automação do navegador: %v", err)
	}

	return nil
}

type ExecConfig struct {
	URL              string
	Payload          string
	Proxy            string
	CollectHAR       bool
	CollectScreenshot bool
	Verbose          bool
	Headless         bool
	OutputPath       string
}

func ExecuteBrowserAutomation(config ExecConfig) error {
	// Implementação da automação do navegador
	return nil
}