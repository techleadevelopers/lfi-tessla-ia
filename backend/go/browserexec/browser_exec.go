package browserexec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"
)

type BrowserRequest struct {
	URL     string `json:"url"`
	Payload string `json:"payload"`
}

type BrowserResponse struct {
	Success bool   `json:"success"`
	Body    string `json:"body"`
}

// 🔌 Modo remoto: envia para microserviço Puppeteer stealth via HTTP
func ExecutarNoBrowser(url, payload string) (BrowserResponse, error) {
	data := BrowserRequest{URL: url, Payload: payload}
	jsonData, _ := json.Marshal(data)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("http://127.0.0.1:7777/execute", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return BrowserResponse{}, err
	}
	defer resp.Body.Close()

	var response BrowserResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	return response, err
}

// 🧪 Modo local: roda Node+Puppeteer inline, sem microserviço
func HeadlessPayloadExec(targetURL string, payload string) error {
	script := fmt.Sprintf(`
		const puppeteer = require('puppeteer');
		(async () => {
			const browser = await puppeteer.launch({ headless: true });
			const page = await browser.newPage();
			await page.goto('%s');
			await page.evaluate(() => {
				let input = document.createElement('input');
				input.name = "injection";
				input.value = "%s";
				document.body.appendChild(input);
			});
			await page.screenshot({ path: 'browser_exec_result.png' });
			await browser.close();
		})();
	`, targetURL, payload)

	cmd := exec.Command("node", "-e", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("erro ao iniciar browser: %v", err)
	}

	done := make(chan error)
	go func() { done <- cmd.Wait() }()

	select {
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		return fmt.Errorf("⏱️ Timeout: processo matou após 20s")
	case err := <-done:
		if err != nil {
			return fmt.Errorf("Erro browser exec: %v\nOutput: %s", err, out.String())
		}
	}

	return nil
}
