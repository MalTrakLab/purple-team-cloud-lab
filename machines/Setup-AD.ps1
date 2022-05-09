function Execute-WhenOnline {

    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string] $IPAddress,
        [Parameter(Mandatory=$true, Position=1)]
        [System.Management.Automation.PSCredential] $Credential,
        [Parameter(Mandatory=$true, Position=2)]
        [System.Management.Automation.ScriptBlock] $ScriptBlock,
        [Int] $MAX_WAIT = 60
    )

    do {
        Write-Host "waiting..."
        Start-Sleep $MAX_WAIT
        $options = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $Session = New-PSSession -ComputerName $IPAddr -Credential $Credential -UseSSL -SessionOption $options -ErrorAction SilentlyContinue
    } until($Session -ne $null )
    
    Invoke-Command $Session -ScriptBlock $ScriptBlock
    Restart-Computer -ComputerName $IPAddr -Force -ErrorAction SilentlyContinue
    Start-Sleep $MAX_WAIT

}

$IPAddr = $args[0]

#Script For The Domain Controller
$remoteUsername = "Administrator"
$DefaultPassword = "LabPass1"

$securePassword = ConvertTo-SecureString -AsPlainText -Force $DefaultPassword
$cred = New-Object System.Management.Automation.PSCredential $remoteUsername, $securePassword

#Rename The Domain Controller & Restart
Execute-WhenOnline $IPAddr -Credential $cred -ScriptBlock {
    $NewComputerName = "DCLabLocal"
    Write-Output "Renaming Server" | Out-File  C:/Log.txt -Append
    Rename-Computer -NewName $NewComputerName -PassThru -ErrorAction Stop
    Restart-Computer -Force -ErrorAction SilentlyContinue
}

#Install Active Directory & DNS Server
Execute-WhenOnline $IPAddr -Credential $cred -ScriptBlock {
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -ErrorAction Stop -Confirm:$false
    Install-WindowsFeature DNS -IncludeManagementTools -ErrorAction Stop -Confirm:$false    #-NoRebootOnCompletion
}

#Setup DNS Server & AD Forest
Execute-WhenOnline $IPAddr -Credential $cred -ScriptBlock {
    $ForestName = "adlab.local"
    $DefaultPassword = "LabPass1"
    $DomainControllerIPaddress = "192.168.10.100"
    $InterfaceIndex = 4
    Write-Output "Installing Active Directory" | Out-File  C:/Log.txt -Append
    Install-ADDSForest -DomainName $ForestName -InstallDNS -SafeModeAdministratorPassword (ConvertTo-SecureString $DefaultPassword -AsPlainText -Force) -Force 
    $netInterface = Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPv4Address,InterfaceIndex | Sort-Object InterfaceIndex
    foreach($obj in $netInterface)
    {
        if ($obj.IPv4Address -cmatch "192.168.10.*") {
            $InterfaceIndex = $obj.InterfaceIndex
        }
    }
    Add-DnsServerPrimaryZone -NetworkID 192.168.10.0/24 -ZoneFile “192.168.10.100.in-addr.arpa.dns”
    Add-DnsServerForwarder -IPAddress 8.8.8.8 -PassThru
    Test-DnsServer -IPAddress 192.168.10.100 -ZoneName "adlab.local"
    Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses ($DomainControllerIPaddress) -ErrorAction Stop
    Restart-Computer -Force -ErrorAction SilentlyContinue
    Start-Sleep 1200
}

#Installing Different Useful Tools
Execute-WhenOnline $IPAddr -Credential $cred -ScriptBlock {
    $DefaultPassword = "LabPass1"

    #Adding Users to AD
    Write-Output "Adding New Users" | Out-File  C:/Log.txt -Append
    New-ADUser -Name "Kimberly Baehr" -GivenName "Kimberly" -Surname "Baehr" -SamAccountName "kbaehr" -AccountPassword (ConvertTo-SecureString $DefaultPassword -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
    New-ADUser -Name "Sarah Looney" -GivenName "Sarah" -Surname "Looney" -SamAccountName "slooney" -AccountPassword (ConvertTo-SecureString $DefaultPassword -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
    New-ADUser -Name "David Dean" -GivenName "David" -Surname "Dean" -SamAccountName "ddean" -AccountPassword (ConvertTo-SecureString $DefaultPassword -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true 
    Add-ADGroupMember -Identity "Domain Admins" -Members "ddean" -Confirm:$false

    #Group Policy - Disable Windows Defender
    Write-Output "Disable Windows Defender" | Out-File  C:/Log.txt -Append
    New-GPO -Name "Disable Windows Defender" -Comment "This policy disables windows defender" -ErrorAction Stop
    Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Type DWord -Value 1
    Set-GPRegistryValue -Name "Disable Windows Defender" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 1                
    New-GPLink -Name "Disable Windows Defender" -Target ((Get-ADDomain).DistinguishedName)

    #Add Shares
    Write-Output "Adding New Shares" | Out-File  C:/Log.txt -Append
    New-Item -Path "C:\Share" -Type Directory -ErrorAction SilentlyContinue
    New-SmbShare -Name "Share" -Path "C:\Share" -ErrorAction SilentlyContinue

    #Install Chocolatey
    Write-Output "Installing Chocolatey" | Out-File  C:/Log.txt -Append
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

    #Installing Important Packages
    Write-Output "Installing Choco Packages" | Out-File  C:/Log.txt -Append
    choco install googlechrome -y --ignore-checksums | Out-Null
    choco install sysmon -y | Out-Null
    choco install winlogbeat -y | Out-Null
    choco install wireshark -y | Out-Null
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

#Adding Users & Finishing Configuration
Execute-WhenOnline $IPAddr -Credential $cred -ScriptBlock {
   
    #Starting winlogbeat
    start-service winlogbeat
    Get-Content "C:\Log.txt"
}

