package browserexec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"
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

// ExecutarNoBrowser envia um payload para um microserviço Puppeteer via HTTP.
// Este modo permite delegar a execução do browser para um serviço separado.
// Retorna a resposta do serviço ou um erro em caso de falha na comunicação.
func ExecutarNoBrowser(url, payload string) (BrowserResponse, error) {
	data := BrowserRequest{URL: url, Payload: payload}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return BrowserResponse{}, fmt.Errorf("ExecutarNoBrowser: erro ao serializar request JSON: %v", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post("http://127.0.0.1:7777/execute", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return BrowserResponse{}, fmt.Errorf("ExecutarNoBrowser: erro ao enviar request HTTP para o microserviço: %v", err)
	}
	defer resp.Body.Close()

	var response BrowserResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return BrowserResponse{}, fmt.Errorf("ExecutarNoBrowser: erro ao decodificar resposta JSON do microserviço: %v", err)
	}

	return response, nil
}

// HeadlessPayloadExec executa o Puppeteer localmente de forma headless com stealth plugins.
// Injeta o payload na página alvo via tag <script> e coleta DOM, cookies e um screenshot.
// Os resultados são salvos em arquivos locais (dom_result.html, cookies.json, screenshot.png).
// Retorna um erro se houver falha ao iniciar ou executar o browser.
func HeadlessPayloadExec(targetURL string, payload string) error {
	escapedPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("HeadlessPayloadExec: erro ao escapar o payload para injeção: %v", err)
	}

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

			await page.evaluate((url, scriptContent) => {
				let el = document.createElement('script');
				el.innerHTML = scriptContent;
				document.body.appendChild(el);
			}, '%s', JSON.stringify(%s));

			const domDump = await page.content();
			const cookies = await page.cookies();
			const screenshot = await page.screenshot({ encoding: 'binary' });

			fs.writeFileSync('dom_result.html', domDump);
			fs.writeFileSync('cookies.json', JSON.stringify(cookies, null, 2));
			fs.writeFileSync('screenshot.png', screenshot);

			await browser.close();
		})();
	`, targetURL, targetURL, string(escapedPayload))

	cmd := exec.Command("node", "-e", puppeteerConfig)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("HeadlessPayloadExec: erro ao iniciar processo do Node.js: %v", err)
	}

	done := make(chan error)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("HeadlessPayloadExec: ⏱️ Timeout: processo do Node.js interrompido após 60 segundos")
	case err := <-done:
		if err != nil {
			return fmt.Errorf("HeadlessPayloadExec: erro ao executar o script do Node.js: %v\nOutput: %s", err, out.String())
		}
	}

	return nil
}

// HeadlessPayloadExecWithLogs executa o Puppeteer localmente de forma headless com stealth plugins e logs detalhados.
// Similar a HeadlessPayloadExec, mas com mensagens de log no console para acompanhar a execução do Puppeteer.
// Retorna um erro se houver falha ao iniciar ou executar o browser.
func HeadlessPayloadExecWithLogs(targetURL string, payload string) error {
	escapedPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("HeadlessPayloadExecWithLogs: erro ao escapar o payload para injeção: %v", err)
	}

	puppeteerConfig := fmt.Sprintf(`
		const puppeteer = require('puppeteer-extra');
		const StealthPlugin = require('puppeteer-extra-plugin-stealth');
		const fs = require('fs');

		puppeteer.use(StealthPlugin());

		(async () => {
			console.log('HeadlessPayloadExecWithLogs: Iniciando navegador...');
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

			console.log('HeadlessPayloadExecWithLogs: Navegador iniciado. Acessando página: %%s', '%s');
			const page = await browser.newPage();
			await page.setExtraHTTPHeaders({
				'Accept-Language': 'en-US,en;q=0.9',
				'Accept-Encoding': 'gzip, deflate, br',
				'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
			});

			await page.goto('%s', { waitUntil: 'networkidle2', timeout: 60000 });

			console.log('HeadlessPayloadExecWithLogs: Página acessada. Executando script: %%s', string(%s));
			await page.evaluate((url, scriptContent) => {
				let el = document.createElement('script');
				el.innerHTML = scriptContent;
				document.body.appendChild(el);
			}, '%s', string(%s));

			console.log('HeadlessPayloadExecWithLogs: Script executado. Coletando dados...');
			const domDump = await page.content();
			const cookies = await page.cookies();
			const screenshot = await page.screenshot({ encoding: 'binary' });

			fs.writeFileSync('dom_result.html', domDump);
			fs.writeFileSync('cookies.json', JSON.stringify(cookies, null, 2));
			fs.writeFileSync('screenshot.png', screenshot);

			console.log('HeadlessPayloadExecWithLogs: Dados coletados. Fechando navegador...');
			await browser.close();
		})();
	`, targetURL, targetURL, targetURL, escapedPayload, targetURL, escapedPayload)

	cmd := exec.Command("node", "-e", puppeteerConfig)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("HeadlessPayloadExecWithLogs: erro ao iniciar processo do Node.js: %v", err)
	}

	done := make(chan error)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("HeadlessPayloadExecWithLogs: ⏱️ Timeout: processo do Node.js interrompido após 60 segundos")
	case err := <-done:
		if err != nil {
			return fmt.Errorf("HeadlessPayloadExecWithLogs: erro ao executar o script do Node.js: %v\nOutput: %s", err, out.String())
		}
	}

	return nil
}

// IntegracaoBurp tenta interagir com o Burp Suite usando sua API REST.
// Atualmente, a implementação está incompleta e requer o uso da API REST da Burp Suite
// (fornecida por uma extensão como 'burp-rest-api' da VMware).
// A função precisará ser refatorada para fazer requisições HTTP para a API REST do Burp.
// Retorna um erro se a inicialização da API falhar (atualmente, falhará devido à falta da biblioteca).
func IntegracaoBurp(url, payload string) error {
	return fmt.Errorf("IntegracaoBurp: funcionalidade de integração com Burp Suite via API REST não implementada. Consulte a documentação da 'burp-rest-api' para detalhes de implementação")
}

// ExecConfig é uma struct para configurar a automação do navegador (atualmente não utilizada).
type ExecConfig struct {
	URL             string
	Payload         string
	Proxy           string
	CollectHAR      bool
	CollectScreenshot bool
	Verbose         bool
	Headless        bool
	OutputPath      string
}

// ExecuteBrowserAutomation é uma função de placeholder para a automação do navegador (atualmente não implementada).
// A lógica para controlar um navegador headless com funcionalidades específicas seria implementada aqui.
// Retorna sempre nil (sucesso) por enquanto.
func ExecuteBrowserAutomation(config ExecConfig) error {
	fmt.Println("ExecuteBrowserAutomation: A automação do navegador configurada não está implementada.")
	return nil
}