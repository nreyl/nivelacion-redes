# capturar-win.ps1 — Captura descifrada en Windows. Uso:  ./capturar-win.ps1  [url]
param([string]$Url = "https://alpespay.datoid.co/")
$KeyLog  = "$HOME\alpes_keys.log"
$Profile = "$env:TEMP\alpes-chrome"
"" | Out-File -Encoding ascii $KeyLog

# Configurar Wireshark para descifrar
$prefs = "$env:APPDATA\Wireshark\preferences"
New-Item -ItemType Directory -Force -Path (Split-Path $prefs) | Out-Null
$lines = @()
if (Test-Path $prefs) { $lines = Get-Content $prefs | Where-Object { $_ -notmatch '^\s*tls.keylog_file:' } }
$lines + "tls.keylog_file: $KeyLog" | Set-Content -Encoding ascii $prefs

Write-Host "Claves TLS -> $KeyLog"
Write-Host "Wireshark  -> configurado. El lab es REMOTO: captura en tu adaptador de red real (Wi-Fi/Ethernet), NO en loopback. Filtro: tcp.port == 9010"

$chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $chrome)) { $chrome = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" }
$env:SSLKEYLOGFILE = $KeyLog
& $chrome --user-data-dir="$Profile" --ignore-certificate-errors --test-type --new-window $Url
