# CAR → Sysmon Event ID → EQL Mapping

This document maps each MITRE CAR analytic used in the lab to the corresponding Sysmon Event ID and the EQL rule implemented in Kibana.

---

## How to read this table

The CAR pseudocode defines the **detection logic** in an abstract form. The Sysmon Event ID is the **concrete log source** on Windows. The EQL rule is the **implementation** in Kibana Elastic SIEM.

---

## Phase 1 — T1566.001 Spearphishing Attachment

| Field | Value |
|-------|-------|
| CAR Analytic | CAR-2019-04-002 |
| Sysmon Event ID | 1 (ProcessCreate) |
| Key fields | `Image`, `ParentImage`, `CommandLine` |

**CAR Pseudocode:**
```
process = search Process:Create
where process.image contains "powershell" OR "cmd" OR "wscript" OR "cscript"
  AND process.parent_image contains "outlook" OR "winword" OR "excel"
```

**EQL (Kibana):**
```eql
process where event.code == "1"
  and process.name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
  and process.parent.name in ("OUTLOOK.EXE", "WINWORD.EXE", "EXCEL.EXE")
```

**Note:** In this lab the payload was executed directly (no Office parent), so the rule was adapted to monitor the initial process creation of the payload binary.

---

## Phase 2 — T1059.001 PowerShell Execution

| Field | Value |
|-------|-------|
| CAR Analytic | CAR-2014-04-003 |
| Sysmon Event ID | 1 (ProcessCreate) |
| Key fields | `Image: powershell.exe`, `ParentImage`, `CommandLine` |

**CAR Pseudocode:**
```
process = search Process:Create
where process.image = "powershell.exe"
  AND process.parent_image != "explorer.exe"
```

**EQL (Kibana):**
```eql
process where event.code == "1"
  and process.name == "powershell.exe"
  and process.parent.name != "explorer.exe"
```

**Kibana results:** 21 events detected from `Guest-Windows`

---

## Phase 3 — T1055 Process Injection

| Field | Value |
|-------|-------|
| CAR Analytic | CAR-2020-11-003 |
| Sysmon Event ID | 8 (CreateRemoteThread) |
| Key fields | `SourceImage`, `TargetImage`, `StartAddress` |

**CAR Pseudocode:**
```
thread = search Thread:Create
where thread.target_process_image != thread.source_process_image
  AND thread.source_process_image NOT IN (known_legitimate_sources)
```

**EQL (Kibana):**
```eql
process where event.code == "8"
  and winlog.event_data.TargetImage like~ "*notepad.exe"
```

**Note:** Sysmon EID 8 requires explicit `CreateRemoteThread onmatch: include` in the Sysmon config. The default SwiftOnSecurity config excludes known-good sources (svchost, wininit, csrss) but does not include unknown sources by default.

---

## Phase 4 — T1003.001 LSASS Memory Dump

| Field | Value |
|-------|-------|
| CAR Analytic | CAR-2019-08-001 |
| Sysmon Event ID | 10 (ProcessAccess) |
| Key fields | `TargetImage: lsass.exe`, `GrantedAccess` |

**CAR Pseudocode:**
```
process = search Process:Access
where process.target_process_image = "lsass.exe"
  AND process.granted_access contains READ_PROCESS_MEMORY
```

**EQL (Kibana):**
```eql
process where event.code == "10"
  and winlog.event_data.TargetImage like~ "*lsass.exe"
  and winlog.event_data.GrantedAccess in ("0x1010", "0x1410", "0x1438", "0x143a")
```

**GrantedAccess flags explained:**

| Flag | Meaning |
|------|---------|
| 0x1010 | PROCESS_VM_READ + PROCESS_QUERY_LIMITED_INFORMATION |
| 0x1410 | Above + PROCESS_QUERY_INFORMATION |
| 0x1438 | Full read access — typical of Mimikatz |
| 0x143a | Full read + write — aggressive dumping |

**Sysmon config required:**
```xml
<ProcessAccess onmatch="include">
  <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
</ProcessAccess>
```

---

## Phase 5 — T1041 Exfiltration over C2

| Field | Value |
|-------|-------|
| CAR Analytic | CAR-2013-10-002 |
| Sysmon Event ID | 3 (NetworkConnect) |
| Key fields | `Image`, `DestinationIp`, `DestinationPort` |

**CAR Pseudocode:**
```
flow = search Network:Connection
where flow.src_process_image = "powershell.exe"
  AND flow.dest_ip NOT IN (known_good_destinations)
  AND flow.dest_port NOT IN (80, 443)
```

**EQL (Kibana):**
```eql
network where event.code == "3"
  and process.name == "powershell.exe"
  and destination.ip != "127.0.0.1"
```