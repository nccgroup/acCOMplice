# acCOMplice

_Your COM hijacking accomplice_

Author: David Tulis ([@kafkaesqu3](https://twitter.com/kafkaesqu3))

## Overview

This repository contains code samples and proofs-of-concept for exploring COM
hijacking. COM hijacking is a Windows post exploitation technique, which can be
used for persistence or defense evasion. 

For more information on the COM interface, how to find hijacks, and techniques
for abusing a hijack, please refer to the presentation given at Derbycon 9,
_COM Hijacking Techniques_.

* Slides: <https://www.slideshare.net/DavidTulis1/com-hijacking-techniques-derbycon-2019>
* Presentation: <https://www.youtube.com/watch?v=pH14BvUiTLY>

## Project

* **COMHijackToolkit:** Powershell script containing helper scripts for dealing
                        with COM hijacks. Quick highlights: 
    * `Extract-HijackableKeysFromProcmonCSV`: parses a Procmon CSV export for
                                              hijackable objects
    * `Hijack-CLSID`: Hijacks a CLSID with a given DLL
    * `Hijack-MultipleKeys`: Hijacks multiple CLSDs concurrently with a given
                             DLL. This is useful for finding CLSIDs which are
                             activated often
* **InjectionTemplates:** 3 templates demoed at Derbycon presentation
    * Create a new process with `CreateProcess`
    * Inject into an existing process with `CreateRemoteThread`
    * Measure thread lifetimes in current process using `CreateThread`
* **COMinject:** Proof of concept demonstrating how COM hijacks can be used to accomplish process injections/migrations
* **masterkeys.csv:** Some keys for you to play with
* **procmon-filters:** Filters for Procmon to aid in hijack identification and
               exploitation

## Examples

### COMHijackToolkit

Powershell script containing helper scripts for dealing with COM hijacks. Highlights:

Show all COM object CLSIDs and the location of the implementation on disk
```
$keys = Get-CLSIDRegistryKeys -RegHive HKCR
$results = $keys | % {$guid = Extract-GUIDFromText $_; Map-GUIDToDLL -guid $guid 2> $null }
```

Conduct a survey of CLSIDs on a system
```
$HKCR_keys = Get-CLSIDRegistryKeys -RegHive HKCR
$HKCR_keys | where-object {$_ -like "*inprocserver"} | Measure-Object
$HKCR_keys | where-object {$_ -like "*inprocserver32"} | Measure-Object
$HKCR_keys | where-object {$_ -like "*localserver"} | Measure-Object
$HKCR_keys | where-object {$_ -like "*localserver32"} | Measure-Object

$HKLM_keys = Get-CLSIDRegistryKeys -RegHive HKLM
$HKLM_keys | Measure-Object
$HKCU_keys = Get-CLSIDRegistryKeys -RegHive HKCU
$HKCU_keys | Measure-Object
```
```
explorer:{69486DD6-C19F-42e8-B508-A53F9F8E67B8}
explorer:{9E175B6D-F52A-11D8-B9A5-505054503030}
explorer:{30CC9D06-7E62-4966-9777-BC3442E788BD}
explorer:{3eef301f-b596-4c0b-bd92-013beafce793}
explorer:{682159d9-c321-47ca-b3f1-30e36b2ec8b9}
explorer:{6B3B8D23-FA8D-40B9-8DBD-B950333E2C52}
explorer:{9aa46009-3ce0-458a-a354-715610a075e6}
explorer:{9BA05972-F6A8-11CF-A442-00A0C90A8F39}
explorer:{AC36A05C-FB95-4C7A-868C-A43CC8D2D926}
explorer:{B52D54BB-4818-4EB9-AA80-F9EACD371DF8}
explorer:{c2f03a33-21f5-47fa-b4bb-156362a2f239}
```

Find CLSIDs referencing a DLL which does not exist on the system: 
```
Find-MissingLibraries
```

### InjectionTemplates

3 proof-of-concept templates for COM hijack abuse, as demonstrated in the
Derbycon 9 presentation: 

* `HijackDLL-Process`: Create a new process when DLL is loaded
* `HijackDLL-CreateRemoteThread`: Perform thread injection technique using
                                  `CreateRemoteThread` API call when DLL is
                                  loaded
* `HijackDLL-Threads`: Useful for measuring lifetime of a threads started in the
                       DLL after a hijack

### COMinject

Proof of concept to show how COM hijacking can be used for process injections: 

* _COMInjectDotNet:_ Proof of concept client which will inject a DLL into a
                     supported process via COM hijack
* _COMInjectTarget:_ The target library to inject into a process

The first step is to perform the hijack:

```
COMInjectDotNet.exe chrome.exe C:\COM\COMInjectTarget.dll
```

The hijack won't trigger immediately, and may require the application to be
started (if not currently running), or some basic application actions. There are
probably some better CLSIDs that trigger more often, but these are good enough. 

The `COMInjectTarget.dll` will log its progress to a log file in `C:\COM`. This
appears more stable than using something like `AllocConsole` from within another
process and just printing to the console.

The following shows the injected DLL running from within the main `chrome.exe`
process:

```
[*] chrome pid=9104 ppid=4900 (count 0)
[*] chrome pid=9104 ppid=4900 (count 1)
[*] chrome pid=9104 ppid=4900 (count 2)
[*] chrome pid=9104 ppid=4900 (count 3)
[*] chrome pid=9104 ppid=4900 (count 4)
[*] chrome pid=9104 ppid=4900 (count 5)
``` 

The currently supported processes are:

* explorer (default)
* chrome
* excel
* word
* outlook

## References and credits
To learn more about COM and COM hijacks: 

* Leo Loobeek ([@leoloobeek](https://twitter.com/leoloobeek)):
    * [COMProxy](https://github.com/leoloobeek/COMProxy/), which I borrowed code
      heavily from
    * [Proxying COM For Stable Hijacks](https://adapt-and-attack.com/2019/08/29/proxying-com-for-stable-hijacks/)
* Matt Nelson ([@enigma0x3](https://twitter.com/enigma0x3)):
    * [Userland Persistence with Scheduled Tasks and COM Handler Hijacking](https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/)
* The [@bohops](https://twitter.com/bohops) series on COM hijacks:
    * [Abusing the COM Registry Structure: CLSID, LocalServer32, & InprocServer32](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)
    * [Abusing the COM Registry Structure (Part 2): Hijacking & Loading Techniques](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)
* James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo)):
    * [Having Fun with COM](https://vimeo.com/showcase/5637718/video/335942580)
    * [COM in 60 seconds](https://www.youtube.com/watch?v=dfMuzAZRGm4)
    * [OleViewDotNet](https://github.com/tyranid/oleviewdotnet)
* Casey Smith ([@subtee](https://twitter.com/subtee)) + [@enimga0x3](https://twitter.com/enimga0x3):
    * [Windows Operating System Archaeology](https://www.youtube.com/watch?v=3gz1QmiMhss) ([slides](https://www.slideshare.net/enigma0x3/windows-operating-system-archaeology), [code](https://github.com/jeperez/windows-operating-system-archaeology))


