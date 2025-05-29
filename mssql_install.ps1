#Requires -RunAsAdministrator

<#
.SYNOPSIS
    MS SQL Server silent installation script

.DESCRIPTION
    This script installs MS SQL Server unattended from the ISO image.
    Transcript of entire operation is recorded in the log file.

    The script lists parameters provided to the native setup but hides sensitive data. See the provided
    links for SQL Server silent install details.
.NOTES
    Version: 1.1
#>

param(
    # Path to ISO file, if empty and current directory contains single ISO file, it will be used.
    [string] $IsoPath = $ENV:SQLSERVER_ISOPATH,

    # Sql Server features, see https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-2016-from-the-command-prompt#Feature
    [ValidateSet('SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase', 'AdvancedAnalytics', 'AS', 'RS', 'DQC', 'IS', 'MDS', 'SQL_SHARED_MR', 'Tools', 'BC', 'BOL', 'Conn', 'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB')]
    [string[]] $Features = @('SQLEngine', 'FullText', 'IS'),

    # Specifies a nondefault installation directory
    [string] $InstallDir,

    # Data directory, by default "$Env:ProgramFiles\Microsoft SQL Server"
    [string] $DataDir,

    # Service name. Mandatory, by default MSSQLSERVER
    [ValidateNotNullOrEmpty()]
    [string] $InstanceName = 'MSSQLSERVER',

    # sa user password. If empty, SQL security mode (mixed mode) is disabled
    [string] $SaPassword = "P@ssw0rd",

    # Username for the service account, see https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-2016-from-the-command-prompt#Accounts
    # Optional, by default 'NT Service\MSSQLSERVER'
    [string] $ServiceAccountName, # = "$Env:USERDOMAIN\$Env:USERNAME"

    # Password for the service account, should be used for domain accounts only
    # Mandatory with ServiceAccountName
    [string] $ServiceAccountPassword,

    # List of system administrative accounts in the form <domain>\<user>
    # Mandatory, by default current user will be added as system administrator
    [string[]] $SystemAdminAccounts = @("$Env:USERDOMAIN\$Env:USERNAME"),

    # Product key, if omitted, evaluation is used unless VL edition which is already activated
    [string] $ProductKey,

    # Use bits transfer to get files from the Internet
    [switch] $UseBitsTransfer,

    # Enable SQL Server protocols: TCP/IP, Named Pipes
    [switch] $EnableProtocols, 

    #Indicates whether the license is covered under Software Assurance / SQL Subscription
    [string] $PRODUCTCOVEREDBYSA = 'false',

    #Indicates the maxmimum degrees of parallelism. Defaults to 1
    [string] $MAXDOP = '1',

    #SQL Server memory Options, defaults to 12gb min / 24gb max
    [string] $SQLMINMEMORY = '12288',
    [string] $SQLMAXMEMORY = '23815',

    #Set up TempDB 
    [string] $TempDBDir = 'F:\tempDB\',
    [string] $TempDBLogDir = 'F:\tempLog\',
    [string] $TempDBFileSize = '2560',
    [string] $TempDBFileGrowth = '512',
    [string] $TempDBLogSize = '1024',
    [string] $TempDBLogGrowth = '512',
    [string] $TempDBFileCount = '8',

    #Set up user database options
    [string] $UserDBDir = 'D:\sqlData', 
    [string] $UserDBLogDir = 'E:\sqlLogs',

    #SSMS Options
    [switch] $InstallSSMS = $true, 
    [string] $ssmsPath = 'https://aka.ms/ssmsfullsetup', 
    [string] $ssmsInstallPath = '$env:SystemDrive\SSMS',
    [string] $ssmsParams = '/Install /Quiet /NoRestart /Wait'

)


$ErrorActionPreference = 'STOP'
$scriptName = (Split-Path -Leaf $PSCommandPath).Replace('.ps1', '')

<# Code from when we had the temp storage 
# This code was used to move the pagefile, but that required a reboot

### Set up the new pagefile ###

Write-Host "Deleting page file" 
# Remove existing pagefile settings
Get-WmiObject -Query "SELECT * FROM Win32_PageFileSetting" | ForEach-Object { $_.Delete() }

Write-Host "Creating new page file on C:\" 
# Create new pagefile settings
$pageFile = ([WMIClass]"Win32_PageFileSetting").CreateInstance()
$pageFile.Name = "C:\pagefile.sys"
$pageFile.InitialSize = 32768
$pageFile.MaximumSize = 32768
$pageFile.Put()

Write-Host "Changing temp storage from D to  Z"
### Change the Temporary Storage drive from D to Z ###
if (Get-Partition | where DriveLetter -eq 'D') {
Set-Partition -DriveLetter D -NewDriveLetter Z}

End old code #>



$start = Get-Date
Start-Transcript "$PSScriptRoot\$scriptName-$($start.ToString('s').Replace(':','-')).log"


# Expand the C drive
Write-Host "Expanding the C drive to $size.SizeMax"
$size = (Get-PartitionSupportedSize -DriveLetter C)
Resize-Partition -DriveLetter C -Size $size.SizeMax

$dDrive = get-wmiobject win32_volume -filter 'DriveLetter = "D:"'

if ($dDrive) {
    Write-Host "Detected a drive mapped to D: - remapping DVD drive to Y"

    #Change CD drive letter
    $cddrv = Get-WmiObject win32_volume -filter 'DriveLetter = "D:"'
    $cddrv.DriveLetter = "Y:"
    $cddrv.Put() | out-null

}

### Initialize and format new disks ###
Write-Host "Adding new disks"
# Get-Disk | Where partitionstyle -eq 'raw' | Where Number -eq '1' | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter 'D' | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false

# Get-Disk | Where partitionstyle -eq 'raw' | Where Number -eq '2' | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter 'E' | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false

# Get-Disk | Where partitionstyle -eq 'raw' | Where Number -eq '3' | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter 'F' | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false

#Get-Disk | Where partitionstyle -eq 'raw' | Sort-Object -Property Size -Descending | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false


get-disk | where partitionstyle -eq 'raw' | Sort-Object -Property Size -Descending | Select-Object -First 1 | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter 'D' | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false


get-disk | where partitionstyle -eq 'raw' | Sort-Object -Property Size -Descending | Select-Object -First 1 | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter 'E' | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false


get-disk | where partitionstyle -eq 'raw' | Sort-Object -Property Size -Descending | Select-Object -First 1 | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -DriveLetter 'F' | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -Confirm:$false


### Install MSSQL 

if (!$IsoPath) {
    Write-Host "SQLSERVER_ISOPATH environment variable not specified, using defaults"
    #$IsoPath = "https://satftstatestorage.file.core.windows.net/scriptshare/SQLServer2022-x64-ENU-Dev.iso"
    $IsoPath = "https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLServer2022-x64-ENU-Dev.iso"

    $saveDir = Join-Path $Env:TEMP $scriptName
    New-item $saveDir -ItemType Directory -ErrorAction 0 | Out-Null

    $isoName = $isoPath -split '/' | Select-Object -Last 1
    $savePath = Join-Path $saveDir $isoName

    if (Test-Path $savePath){
        Write-Host "ISO already downloaded, checking hashsum..."
        $hash    = Get-FileHash -Algorithm MD5 $savePath | % Hash
        $oldHash = Get-Content "$savePath.md5" -ErrorAction 0
    }

    if ($hash -and $hash -eq $oldHash) { Write-Host "Hash is OK" } else {
        if ($hash) { Write-Host "Hash is NOT OK"}
        Write-Host "Downloading: $isoPath"

        if ($UseBitsTransfer) {
            Write-Host "Using bits transfer"
            $proxy = if ($ENV:HTTP_PROXY) { @{ ProxyList = $ENV:HTTP_PROXY -replace 'http?://'; ProxyUsage = 'Override' }} else { @{} }
            Start-BitsTransfer -Source $isoPath -Destination $saveDir @proxy
        }  else {
            Invoke-WebRequest $IsoPath -OutFile $savePath -UseBasicParsing -Proxy $ENV:HTTP_PROXY
        }

        Get-FileHash -Algorithm MD5 $savePath | % Hash | Out-File "$savePath.md5"
    }

    $IsoPath = $savePath
}

Write-Host "`IsoPath: " $IsoPath


$volume = Mount-DiskImage $IsoPath -StorageType ISO -PassThru | Get-Volume
$iso_drive = if ($volume) {
    $volume.DriveLetter + ':'
} else {
    # In Windows Sandbox for some reason Get-Volume returns nothing, so lets look for the ISO description
    Get-PSDrive | ? Description -like 'sql*' | % Root
}
if (!$iso_drive) { throw "Can't find mounted ISO drive" } else { Write-Host "ISO drive: $iso_drive" }

Get-ChildItem $iso_drive | ft -auto | Out-String

Get-CimInstance win32_process | ? { $_.commandLine -like '*setup.exe*/ACTION=install*' } | % {
    Write-Host "Sql Server installer is already running, killing it:" $_.Path  "pid: " $_.processId
    Stop-Process $_.processId -Force
}

$cmd =@(
    "${iso_drive}setup.exe"
    '/Q'                                          # Silent install
    '/INDICATEPROGRESS'                           # Specifies that the verbose Setup log file is piped to the console
    '/IACCEPTSQLSERVERLICENSETERMS'               # Must be included in unattended installations
    '/PRODUCTCOVEREDBYSA=$PRODUCTCOVEREDBYSA'     # Indicates whether product licensing is covered by Software Assurance
    '/ACTION=install'                             # Required to indicate the installation workflow
    '/UPDATEENABLED=false'                        # Should it discover and include product updates.

    "/INSTANCEDIR=""$InstallDir"""
    "/INSTALLSQLDATADIR=""$DataDir"""

    "/FEATURES=" + ($Features -join ',')

    '/SQLMAXDOP=$MAXDOP' 

    '/SQLMINMEMORY=$SQLMINMEMORY'
    '/SQLMAXMEMORY=$SQLMAXMEMORY'

    #TempDB Options
    '/SQLTEMPDBDIR=$TempDBDir'
    '/SQLTEMPDBLOGDIR=$TempDBLogDir'
    '/SQLTEMPDBFILESIZE=$TempDBFileSize'
    '/SQLTEMPDBFILEGROWTH=$TempDBFileGrowth'
    '/SQLTEMPDBLOGFILESIZE=$TempDBLogSize'
    '/SQLTEMPDBLOGFILEGROWTH=$TempDBLogGrowth'
    '/SQLTEMPDBFILECOUNT=$TempDBFileCount'

    #UserDB Options
    '/SQLUSERDBDIR=$UserDBDir'
    '/SQLUSERDBLOGDIR=$UserDBLogDir'

    #Security
    "/SQLSYSADMINACCOUNTS=""$SystemAdminAccounts"""
    '/SECURITYMODE=SQL'                 # Specifies the security mode for SQL Server. By default, Windows-only authentication mode is supported.
    "/SAPWD=""$SaPassword"""            # Sa user password

    "/INSTANCENAME=$InstanceName"       # Server instance name

    "/SQLSVCACCOUNT=""$ServiceAccountName"""
    "/SQLSVCPASSWORD=""$ServiceAccountPassword"""

    # Service startup types
    "/SQLSVCSTARTUPTYPE=automatic"
    "/AGTSVCSTARTUPTYPE=automatic"
    "/ASSVCSTARTUPTYPE=manual"

    "/PID=$ProductKey"

)

# remove empty arguments
$cmd_out = $cmd = $cmd -notmatch '/.+?=("")?$'

# show all parameters but remove password details
Write-Host "Install parameters:`n"
'SAPWD', 'SQLSVCPASSWORD' | % { $cmd_out = $cmd_out -replace "(/$_=).+", '$1"****"' }
$cmd_out[1..100] | % { $a = $_ -split '='; Write-Host '   ' $a[0].PadRight(40).Substring(1), $a[1] }
Write-Host

"$cmd_out"
Invoke-Expression "$cmd"
if ($LastExitCode) {
    if ($LastExitCode -ne 3010) { throw "SqlServer installation failed, exit code: $LastExitCode" }
    Write-Warning "SYSTEM REBOOT IS REQUIRED"
}

if ($EnableProtocols) {
    function Enable-Protocol ($ProtocolName) { $sqlNP | ? ProtocolDisplayName -eq $ProtocolName | Invoke-CimMethod -Name SetEnable }

    Write-Host "Enable SQL Server protocols: TCP/IP, Named Pipes"

    $sqlCM = Get-CimInstance -Namespace 'root\Microsoft\SqlServer' -ClassName "__NAMESPACE"  | ? name -match 'ComputerManagement' | Select-Object -Expand name
    $sqlNP = Get-CimInstance -Namespace "root\Microsoft\SqlServer\$sqlCM" -ClassName ServerNetworkProtocol

    Enable-Protocol 'TCP/IP'
    Enable-Protocol 'Named Pipes'

    Get-Service $InstanceName | Restart-Service -Force
}

Dismount-DiskImage $IsoPath


if($InstallSSMS) {

    Write-Host "Downloading: $ssmsPath"

        $ssmsIsoName = $ssmsPath -split '/' | Select-Object -Last 1
        $ssmsExeName = $ssmsIsoName + ".exe" 
        $ssmsSavePath = Join-Path $saveDir $ssmsExeName


        if ($UseBitsTransfer) {
            Write-Host "Using bits transfer"
            $proxy = if ($ENV:HTTP_PROXY) { @{ ProxyList = $ENV:HTTP_PROXY -replace 'http?://'; ProxyUsage = 'Override' }} else { @{} }
            Start-BitsTransfer -Source $ssmsPath -Destination $ssmsSavePath @proxy
        }  else {
            Invoke-WebRequest $ssmsPath -OutFile $ssmsSavePath -UseBasicParsing -Proxy $ENV:HTTP_PROXY
        }

    $SSMSInstall = "$ssmsSavePath $ssmsParams"
    Write-Host "Installing SSMS using $SSMSInstall" 
    Invoke-Expression $SSMSInstall
}

"`nInstallation length: {0:f1} minutes" -f ((Get-Date) - $start).TotalMinutes
trap { Stop-Transcript; if ($IsoPath) { Dismount-DiskImage $IsoPath -ErrorAction 0 } }
Stop-Transcript
