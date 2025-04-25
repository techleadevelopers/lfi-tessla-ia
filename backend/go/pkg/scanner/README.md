Scanner Package

The scanner package provides a comprehensive framework to perform automated security scans against LFI/RFI targets. It integrates WebSocket-based logging, entropy and fingerprint analysis, dynamic payload injection, and fallback mutation strategies.

Features

WebSocket Control: Real-time scan events sent to a control server via wscontrol.

Fingerprinting: Passive and active fingerprint collection using utlslocal.

Genetic Population: Initializes an evolutionary population (evolution.LoadPopulation) for adaptive payload success tracking.

Timing Analysis: Measures response time variance to detect side-channel vulnerabilities.

Content Analysis: Detects high entropy, LFI patterns (root:...:0:0:), reflected output, and WAF presence.

Fallback Mutations: Applies simple LFI payload mutations when primary scan fails.

Integration Hooks: Sends reinforcement feedback via aibridge and logs to analyzer and browserexec modules.

Installation

go get lfitessla/scanner

Ensure your project also includes the required dependencies:

go get lfitessla/aibridge lfitessla/analyzer lfitessla/entropy lfitessla/evolution \
    lfitessla/headers lfitessla/http2mux lfitessla/mutador lfitessla/proxy \
    lfitessla/utlslocal lfitessla/wscontrol

Usage

Import the package and call the main orchestration function from your CLI or application:

import "lfitessla/scanner"

func main() {
    alvo := scanner.Alvo{
        URL:    "https://example.com/vuln.php?file=",
        Method: "GET",
        Body:   "",
    }
    payload := "../../../../etc/passwd"

    success := scanner.ExecutarAtaque(alvo, payload)
    if success {
        fmt.Println("Target appears vulnerable")
    } else {
        fmt.Println("No vulnerability detected")
    }
}

API Reference

Types

type Alvo

Alvo struct {
    URL    string // Base URL to test (e.g. https://host/path?param=)
    Method string // HTTP method (GET, POST)
    Body   string // Request body for POST
}

Functions

func ScanAlvoCompleto(fullURL string) bool

Performs the primary WebSocket-based scan on the given fullURL + payload. Returns true if the WebSocket handshake and logging completed.

func ExecutarAtaque(alvo Alvo, payload string) bool

High-level orchestrator. Executes:

ScanAlvoCompleto (WebSocket, fingerprint, evolution init)

executarSonda (timing and content analysis) if initial scan succeeded

executarFallback (simple mutations) if initial scan failed

Returns true if the primary scan succeeded.

func ScanListCompleto(filePath string)

Reads URLs from a file (one per line) and runs ScanAlvoCompleto on each.

Extension Points

Customize fingerprint heuristics in utlslocal.

Hook into aibridge.EnviarFeedbackReforco for RL integration.

Adjust threshold values (entropy, timing variance) in analisarResposta and executarSonda.

Extend executarFallback with more mutation strategies from the mutador package.

Logging & Monitoring

All scan events are emitted via WebSocket to wss://control.tessla.local/scan. Events include:

start-scan, fingerprint, attack-started, time-variance

high-entropy, lfi-detected, reflected-output, waf-detected

Monitor these in your control dashboard for real-time insights.

License

This code is provided under the MIT License. See LICENSE file for details.