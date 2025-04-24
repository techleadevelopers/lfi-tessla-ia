
package headers

import (
	"math/rand"
	"time"
	"net/http"
	"fmt"
)

// Lista realista de user-agents
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/112.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/112.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/113.0.0.0 Safari/537.36",
	"curl/7.85.0",
	"Wget/1.21.1",
	"python-requests/2.28.1",
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

// GerarHeadersRealistas retorna headers furtivos realistas simulando tráfego legítimo
func GerarHeadersRealistas() http.Header {
	headers := http.Header{}
	headers.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	headers.Set("X-Forwarded-For", gerarIPFake())
	headers.Set("Referer", "https://www.google.com/search?q=produto+oficial")
	headers.Set("DNT", "1")
	headers.Set("Upgrade-Insecure-Requests", "1")
	headers.Set("Sec-Ch-Ua", `"Chromium";v="112"`)
	headers.Set("Sec-Fetch-Site", "none")
	headers.Set("Sec-Fetch-Mode", "navigate")
	headers.Set("Accept-Language", "en-US,en;q=0.9")
	headers.Set("Connection", "keep-alive")
	return headers
}

func gerarIPFake() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}
