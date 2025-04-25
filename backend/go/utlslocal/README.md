🧩 Visão Geral do Pacote utlslocal
O pacote utlslocal é responsável por realizar manipulações no nível do handshake TLS com uTLS, simulando clientes reais (ex: Chrome, Firefox, iOS) para evadir WAFs e firewalls com fingerprint TLS alterado. Ele também realiza fingerprinting passivo/ativo e técnicas de evasão avançada.

⚙️ Funcionalidades-Chave

Área Funcional	Finalidade
uTLS Spoofing	Simula handshakes de navegadores reais com ClientHelloID modificados
Fingerprinting HTTP/TLS	Identifica características do servidor para adaptar ataques
Header Order Spoofing	Envia cabeçalhos em ordem customizada para bypasses
Evasão de WAFs	Envia requisições com SNI, headers, User-Agent, ALPN alterados
Proxy-aware Dialer	Suporte a proxies via http.ProxyFromEnvironment()
🔧 Configuração Dinâmica: UTLSConfig
Esta estrutura encapsula uma configuração de handshake TLS modificada, contendo:

HelloID: Identidade do navegador (Chrome, Firefox, etc.)

NextProtos: Protocolos ALPN (ex: http/1.1, h2)

ServerName: SNI real ou fake CDN

CipherSuites: Lista de cipher suites

SignatureAlgorithms: Algoritmos de assinatura

👉 Essa configuração é aleatoriamente gerada por NewRandomUTLSConfig(targetHost).

🌐 Estabelecimento de Conexões com TLS Customizado
DialUTLS(): estabelece conexão TLS com utls.UClient, usando ClientHelloID spoofado.

NewHTTPClient(): retorna um *http.Client configurado com transporte spoofado, útil para todas as requisições automatizadas.

📑 Manipulação de Headers HTTP (Ordem Customizada)
SpoofTransport: um http.RoundTripper customizado que:

Escreve os headers manualmente via conn.Write().

Preserva a ordem dos headers.

Ignora internamente o comportamento padrão do http.Transport.

🧠 Fingerprinting de Servidores
PassiveFingerprint()

Usa uma requisição HEAD para inferir:

Sistema operacional (ex: windows, unix)

Stack da aplicação (ex: php, asp.net, waf-locked)

ActiveFingerprint()

Estende o passivo com payloads comuns (/etc/passwd, etc).

Detecta respostas 403 → indica WAF ativo.

FingerprintTLS()

Extração de:

Versão TLS (1.2 / 1.3)

Cipher Suite (formato 0xXXXX)

Ideal para logging ou fingerprint JA3 manual (em parte comentado).

🔓 Evasão de WAFs – Função EvasaoWAFs()
Executa uma requisição forjada com:

Header spoofado (ordem, user-agent).

SNI falso (Cloudflare, Akamai, etc.).

Transporte uTLS + SpoofTransport.

🧠 Ideal para detectar bloqueios em tempo real e adaptar payloads em sistemas evolutivos.

🔢 Helpers e Utilitários
ExtractHost(): extrai o host de uma URL.

randomUA(): retorna User-Agent realista (hardcoded).

hexUint16(): formata uint16 como string hexadecimal.

logToFile(): salva erros ou fingerprints localmente com timestamp.

🧬 Avançado – Técnicas Futuras / Experimentais
Fragmentação de TLS Records: envia dados TLS em pacotes menores com jitter (simula handshake "quebrado").

InterleavedConn: estrutura que implementa fragmentação controlada no nível TCP.

ClientHelloSpec: montagem manual de mensagens ClientHello (ex: com padding e extensões).

JA3 Fingerprinting (comentado): suporte a JA3 removido por erro de import.

🛡️ Resumo Técnico
O utlslocal fornece:

Spoofing de handshake e fingerprint com uTLS.

Conexão segura e evasiva a WAFs.

Integração com http.Client e headers ordenados.

Suporte embutido a proxy HTTP.

Técnicas preparadas para evolução (fragmentação, JA3, padding...).