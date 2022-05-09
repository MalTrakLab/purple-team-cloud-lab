function Execute-WhenOnline {

    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $IPAddress,
        [Parameter(Mandatory=$true, Position=1)]
        [System.Management.Automation.PSCredential] $Credential,
        [Parameter(Mandatory=$true, Position=2)]
        [System.Management.Automation.ScriptBlock] $ScriptBlock,
        [Int] $MAX_WAIT = 20
    )

    do {
        Write-Host "waiting..."
        Start-Sleep $MAX_WAIT
        $options = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $Session = New-PSSession -ComputerName $IPAddr -Credential $Credential -UseSSL -SessionOption $options -ErrorAction SilentlyContinue
    } until($Session -ne $null )
    
    Invoke-Command $Session -ScriptBlock $ScriptBlock

}
function Get-AllProcesses {
    return Get-Process
}
#Script For The Workstation
$remoteUsername = "Administrator"
$DefaultPassword = "LabPass1"
$IPAddr = $args[0]

$securePassword = ConvertTo-SecureString -AsPlainText -Force $DefaultPassword
$cred = New-Object System.Management.Automation.PSCredential $remoteUsername, $securePassword


Execute-WhenOnline $IPAddr -Credential $cred -ScriptBlock {

    $NewComputerName = "KBAEHR-WORKSTAT"
    $DomainControllerIPaddress = "192.168.10.100"

    #Add Workstation To Active Directory
    Write-Output "Setting DNS Server" | Out-File  C:/Log.txt -Append
    Rename-Computer -NewName $NewComputerName -PassThru -ErrorAction Stop
    $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex | Sort-Object InterfaceIndex
    foreach($obj in $netInterface)
    {
        if ($obj.IPv4Address -cmatch "192.168.10.*") {
            $InterfaceIndex = $obj.InterfaceIndex
        }
    }
    Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses ($DomainControllerIPaddress) -ErrorAction Stop
    Restart-Computer -Force
    Start-Sleep 1200
}

Execute-WhenOnline $IPAddr -Credential $cred -ScriptBlock {
    $DomainName = "adlab.local"
    $remoteUsername = "adlab\kbaehr"
    $DefaultPassword = "LabPass1"

    Write-Output "Connecting To Domain Controller" | Out-File  C:/Log.txt -Append
    $securePassword = ConvertTo-SecureString -AsPlainText -Force $DefaultPassword
    $cred = New-Object System.Management.Automation.PSCredential $remoteUsername, $securePassword

    Add-Computer -DomainName $DomainName -Credential $cred -Force -ErrorAction Stop

    #Add KBAEHR as a workstation admin
    net localgroup "Remote Desktop Users" /add $remoteUsername
    Add-LocalGroupMember -Group "Administrators" -Member $remoteUsername
    Install-Module -Name 'Carbon' -AllowClobber -Force
    Import-Module 'Carbon'
    Grant-Privilege -Identity $remoteUsername -Privilege SeRemoteInteractiveLogonRight

    #Install Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    #Installing Important Packages
    Write-Output "Installing Choco Packages" | Out-File  C:/Log.txt -Append
    choco install googlechrome -y --ignore-checksums
    choco install vscode -y
    choco install sysmon -y
    choco install winlogbeat -y
    choco install wireshark -y
    (New-Object System.Net.WebClient).DownloadFile('https://github.com/iknowjason/BlueTools/blob/main/configs-pc.zip?raw=true', 'C:\ProgramData\chocolatey\lib\configs.zip')
    Expand-Archive -LiteralPath 'C:\ProgramData\chocolatey\lib\configs.zip' -DestinationPath 'C:\ProgramData\chocolatey\lib\configs'
    C:\ProgramData\chocolatey\lib\Sysmon\tools\sysmon.exe -accepteula -i C:\ProgramData\chocolatey\lib\configs\configs-pc\sysmonconfig-export.xml
    (Get-Content C:\ProgramData\chocolatey\lib\configs\configs-pc\winlogbeat.yml) -replace "10.100.1.5", "192.168.20.100" | Set-Content C:\ProgramData\chocolatey\lib\configs\configs-pc\winlogbeat.yml
    Copy-Item "C:\ProgramData\chocolatey\lib\configs\configs-pc\winlogbeat.yml" -Destination "C:\ProgramData\chocolatey\lib\winlogbeat\tools"
    C:\ProgramData\chocolatey\lib\winlogbeat\tools\install-service-winlogbeat.ps1

    Write-Output "Installing Atomic Red Team" | Out-File  C:/Log.txt -Append
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force 
    Install-Module powershell-yaml -Force
    Install-AtomicRedTeam -getAtomics -Force
    Set-ExecutionPolicy Bypass -Force
    Restart-Computer -Force
    Start-Sleep 1200
}

Execute-WhenOnline $IPAddr -Credential $cred -ScriptBlock {
    start-service winlogbeat
    Get-Content "C:\Log.txt"
}