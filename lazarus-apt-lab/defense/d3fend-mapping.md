# D3FEND Countermeasure Mapping

This document maps each ATT&CK technique simulated in the lab to the corresponding MITRE D3FEND countermeasures.

D3FEND answers the question: **"How do we prevent or limit this technique?"**  
CAR answers the question: **"How do we detect this technique?"**

---

## T1566.001 — Spearphishing Attachment

**D3FEND Technique:** File Analysis / Inbound Traffic Filtering

| Countermeasure | D3FEND ID | Implementation |
|----------------|-----------|----------------|
| Inbound traffic filtering | D3-ITF | Block executable attachments (.exe, .hta, .js) at email gateway |
| Dynamic analysis | D3-DA | Sandbox email attachments before delivery (e.g. Microsoft Defender for Office 365) |
| Sender reputation analysis | D3-SRA | Reject emails from unknown or low-reputation senders |

**Windows hardening steps:**
```powershell
# Disable macro execution in Office documents from internet
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Security" `
  -Name "VBAWarnings" -Value 4
```

---

## T1059.001 — PowerShell Execution

**D3FEND Technique:** Execution Isolation / Script Execution Policy Enforcement

| Countermeasure | D3FEND ID | Implementation |
|----------------|-----------|----------------|
| Script execution policy | D3-SEPE | Set PowerShell execution policy to AllSigned |
| Application allowlisting | D3-AAL | Block unauthorized scripts via AppLocker or WDAC |
| Process spawn analysis | D3-PSA | Alert on PowerShell spawned from unexpected parents |

**Windows hardening steps:**
```powershell
# Enforce signed scripts only
Set-ExecutionPolicy AllSigned -Scope LocalMachine -Force

# Enable PowerShell Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1

# Enable PowerShell Constrained Language Mode
[System.Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
```

---

## T1055 — Process Injection

**D3FEND Technique:** Process Isolation / Memory Protection

| Countermeasure | D3FEND ID | Implementation |
|----------------|-----------|----------------|
| Process isolation | D3-PI | Enable Virtualization Based Security (VBS) |
| Memory protection | D3-MP | Enable Arbitrary Code Guard (ACG) via WDEG |
| Credential access protection | D3-CAP | Enable Windows Defender Credential Guard |

**Windows hardening steps:**
```powershell
# Enable Virtualization Based Security
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name "EnableVirtualizationBasedSecurity" -Value 1

# Enable Credential Guard
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name "LsaCfgFlags" -Value 1
```

---

## T1003.001 — LSASS Memory Dump

**D3FEND Technique:** Credential Hardening / LSA Protection

| Countermeasure | D3FEND ID | Implementation |
|----------------|-----------|----------------|
| Credential hardening | D3-CH | Enable LSA Protected Process Light (PPL) |
| Local account monitoring | D3-LAM | Alert on LSASS access from unexpected processes |
| Credential transmission scoping | D3-CTS | Disable WDigest to prevent plaintext caching |

**Windows hardening steps:**
```powershell
# Enable LSA Protection (RunAsPPL)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "RunAsPPL" -Value 1

# Disable WDigest plaintext credential caching
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
  -Name "UseLogonCredential" -Value 0

# Enable Credential Guard
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
  -Name "LsaCfgFlags" -Value 1
```

**Why this matters:**  
With `RunAsPPL` enabled, LSASS runs as a Protected Process Light. Any process attempting to open LSASS with `PROCESS_VM_READ` rights without a valid PPL certificate will receive `ACCESS_DENIED` — Mimikatz fails silently.

---

## T1041 — Exfiltration over C2 Channel

**D3FEND Technique:** Network Traffic Filtering / Protocol Analysis

| Countermeasure | D3FEND ID | Implementation |
|----------------|-----------|----------------|
| Network traffic filtering | D3-NTF | Block outbound connections from powershell.exe via firewall |
| Protocol metadata anomaly detection | D3-PMAD | Detect unusual HTTP patterns (large POST, non-browser UA) |
| DNS traffic analysis | D3-DTA | Monitor for DNS tunneling and high-entropy domain queries |

**Windows hardening steps:**
```powershell
# Block outbound PowerShell network connections via Windows Firewall
New-NetFirewallRule -DisplayName "Block PowerShell Outbound" `
  -Direction Outbound `
  -Program "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -Action Block

# Also block powershell_ise.exe
New-NetFirewallRule -DisplayName "Block PowerShell ISE Outbound" `
  -Direction Outbound `
  -Program "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe" `
  -Action Block
```

---

## Summary Table

| ATT&CK | D3FEND Category | Primary Countermeasure | Effort |
|--------|----------------|----------------------|--------|
| T1566.001 | File Analysis | Email attachment sandboxing | Medium |
| T1059.001 | Execution Isolation | PowerShell AllSigned policy | Low |
| T1055 | Process Isolation | VBS + Credential Guard | High |
| T1003.001 | Credential Hardening | LSA PPL + disable WDigest | Low |
| T1041 | Network Filtering | Firewall block on powershell.exe | Low |

**Effort key:** Low = single registry key / policy change. Medium = requires additional tooling. High = requires hardware support (VT-x/AMD-V) and OS configuration.