# ╔══════════════════════════════════════════════════════════════╗
# ║                  ⚡ LFI TESSLA 2050 - HUD.EXE                ║
# ║        IA • Furtivo • Adaptativo • Reinforcement AI         ║
# ╚══════════════════════════════════════════════════════════════╝

Clear-Host
$FlaskTimeoutSec = 5
$logDir = "logs"
$logFile = "$logDir\lfi_tessla.log"
$flaskProc = $null

Write-Host ""
Write-Host "████████╗███████╗███████╗███████╗██╗     ███████╗ █████╗" -ForegroundColor Cyan
Write-Host "╚══██╔══╝██╔════╝╚══███╔╝██╔════╝██║     ██╔════╝██╔══██╗" -ForegroundColor Cyan
Write-Host "   ██║   █████╗    ███╔╝ █████╗  ██║     █████╗  ███████║" -ForegroundColor Cyan
Write-Host "   ██║   ██╔══╝   ███╔╝  ██╔══╝  ██║     ██╔══╝  ██╔══██║" -ForegroundColor Cyan
Write-Host "   ██║   ███████╗███████╗███████╗███████╗███████╗██║  ██║" -ForegroundColor Cyan
Write-Host "   ╚═╝   ╚══════╝╚══════╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝" -ForegroundColor Cyan
Write-Host ""

Write-Host "🚀 IA embarcada: Mistral 7B  |  Reinforcement AI Payload Loop" -ForegroundColor Green
Write-Host "🧠 Execução: stealth, evasivo, adaptativo, shadow-network mode" -ForegroundColor Green
Write-Host "⚙️  Framework: Go + Flask + Transformers" -ForegroundColor Green
Write-Host ""

# 🔍 Validação de dependências
Write-Host "`n🔍 [1/5] Validando ambiente..." -ForegroundColor Yellow
foreach ($cmd in @("python", "go", "node")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "❌ $cmd não encontrado no sistema." -ForegroundColor Red
        exit 1
    }
}
Start-Sleep -Milliseconds 800

# 🗂 Criar diretório de logs
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

# 🧬 Ambiente virtual Python
Write-Host "`n🔧 [2/5] Ativando ambiente virtual Python..." -ForegroundColor Yellow
Set-Location backend/python/ia_payload_gen
if (-not (Test-Path ".\venv\Scripts\Activate.ps1")) {
    Write-Host "❌ Ambiente virtual não encontrado em ./venv" -ForegroundColor Red
    exit 1
}
. .\venv\Scripts\Activate.ps1
Start-Sleep -Milliseconds 800

# 🧠 Subir Flask (IA)
Write-Host "`n🧬 [3/5] Subindo serviço Flask (IA Payload Generator)..." -ForegroundColor Yellow
Write-Progress -Activity "Subindo Flask" -Status "Aguarde..." -SecondsRemaining $FlaskTimeoutSec

$flaskProc = Start-Process -FilePath "python.exe" -ArgumentList "app.py" `
    -RedirectStandardOutput "../../$logFile" `
    -RedirectStandardError "../../$logFile" `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds $FlaskTimeoutSec

# 🔁 Verificação de saúde da API
Write-Host "`n🌐 [4/5] Verificando status da IA..." -ForegroundColor Yellow
try {
    null = Invoke-WebRequest http://127.0.0.1:5000/healthz -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
    Write-Host "✅ IA operacional: http://127.0.0.1:5000" -ForegroundColor Green
} catch {
    Write-Host "❌ Flask não respondeu corretamente em $FlaskTimeoutSec segundos." -ForegroundColor Red
    if ($flaskProc) { $flaskProc | Stop-Process -Force }
    exit 1
}

# 🚀 Rodar Scanner Go
Write-Host "`n⚙️ [5/5] Executando scanner ofensivo LFI TESSLA (Go)..." -ForegroundColor Yellow
Set-Location ..\..\go\cmd
go run main.go
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Go terminou com erro código $LASTEXITCODE" -ForegroundColor Red
    if ($flaskProc) { $flaskProc | Stop-Process -Force }
    exit $LASTEXITCODE
}

# ✅ Finalização
Write-Host "`n🏁 Execução finalizada. Verifique os arquivos salvos em /vazamentos." -ForegroundColor Magenta
if ($flaskProc) {
    Write-Host "🧼 Encerrando serviço Flask..." -ForegroundColor Yellow
    $flaskProc | Stop-Process -Force
}
Write-Host "`n🎯 EXECUÇÃO CONCLUÍDA — ⚔️ MODO SOMBRA FINALIZADO COM SUCESSO" -ForegroundColor Magenta

