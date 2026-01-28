# Gold Examples: wbadmin NTDS.dit dump / backup abuse (CrowdStrike LogScale CQL)

Purpose: seed the Knowledge Library examples corpus with behavior-first, field-correct CQL patterns.

---

## 1) Inventory: wbadmin executions + command line capture

```cql
#event_simpleName=ProcessRollup2 FileName=wbadmin.exe
| select([@timestamp, ComputerName, UserName, FileName, FilePath, ImageFileName, CommandLine, ParentBaseFileName, ParentCommandLine, ImageHashSha256, SignedStatus])
| groupBy([ComputerName, UserName, FilePath, ImageFileName, ImageHashSha256], limit=20000)
```

## 2) wbadmin start backup + NTDS targets (ntds.dit / Windows\NTDS)

```cql
#event_simpleName=ProcessRollup2 FileName=wbadmin.exe
| regex(CommandLine=/start\s+backup/i)
| regex(CommandLine=/(ntds\.dit|windows\\ntds)/i)
| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=20000)
```

## 3) wbadmin with backuptarget (possible staging to external disk or UNC share)

```cql
#event_simpleName=ProcessRollup2 FileName=wbadmin.exe
| regex(CommandLine=/backuptarget\s*:/i)
| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine], limit=20000)
```

## 4) wbadmin to UNC backuptarget (explicit network path)

```cql
#event_simpleName=ProcessRollup2 FileName=wbadmin.exe
| regex(CommandLine=/backuptarget\s*:\s*\\\\/i)
| groupBy([@timestamp, ComputerName, UserName, FileName, CommandLine], limit=20000)
```

## 5) Suspicious children of wbadmin.exe (post-backup staging or follow-on tooling)

```cql
#event_simpleName=ProcessRollup2 ParentBaseFileName=wbadmin.exe
| in(field=FileName, values=["powershell.exe","cmd.exe","wscript.exe","cscript.exe","rundll32.exe","mshta.exe","regsvr32.exe","curl.exe","bitsadmin.exe","python.exe","node.exe","7z.exe","rar.exe"])
| groupBy([@timestamp, ComputerName, UserName, ParentBaseFileName, ParentCommandLine, FileName, CommandLine, ImageHashSha256], limit=20000)
```
