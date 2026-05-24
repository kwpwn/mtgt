# BYOVD Index

Day la diem bat dau cho nhanh BYOVD. Cac writeup chi tiet duoc tach theo primitive, khong de chung trong mot folder phang nua.

## Files trong folder nay

- `BYOVD_RECENT_WRITEUPS.md`: index cac BYOVD/writeup gan day va y tuong hunting.
- `BYOVD_PRIMITIVE_MATRIX.md`: bang so sanh primitive, do on dinh, rui ro BSOD, version sensitivity.
- `BYOVD_BLOCKLIST_AND_REACHABILITY.md`: model danh gia driver theo loadability, reachability, usefulness va mitigation pressure.

## Folder writeup theo primitive

```text
03_byovd
|-- 00_index-and-matrix
|-- 01_physical-memory-rw
|-- 02_virtual-kernel-rw
|-- 03_process-kill
|-- 04_limited-primitives
|-- 05_msr-and-multi-primitive
`-- 99_workflow
```

## Physical memory R/W

Folder:

```text
03_byovd\01_physical-memory-rw
```

Drivers/writeups:

- `ASTRA64_RW_CODE_WALKTHROUGH.md`
- `ASTRA64_DIRECT_DKOM_DEEP_DIVE.md`
- `LENOVO_LNVMSRIO_DEEP_DIVE.md`
- `THROTTLESTOP_PHYSICAL_RW_DEEP_DIVE.md`
- `ENEIO64_PHYSICAL_RW_DEEP_DIVE.md`
- `PSTRIP64_POWERSTRIP_DEEP_DIVE.md`

## Virtual kernel R/W

Folder:

```text
03_byovd\02_virtual-kernel-rw
```

Drivers/writeups:

- `RTCORE64_MSI_AFTERBURNER_DEEP_DIVE.md`
- `DBUTIL_2_3_DELL_DEEP_DIVE.md`
- `DSARK64_QIHOO_DEEP_DIVE.md`

## Process kill

Folder:

```text
03_byovd\03_process-kill
```

Drivers/writeups:

- `K7RKSCAN_CODE_WALKTHROUGH.md`
- `K7RKSCAN_PROCESS_KILLER_DEEP_DIVE.md`
- `BDAPIUTIL64_CODE_WALKTHROUGH.md`
- `BDAPIUTIL64_PROCESS_KILLER_DEEP_DIVE.md`
- `ZEMANA_TERMINATOR_DEEP_DIVE.md`
- `TFSYSMON_THREATFIRE_DEEP_DIVE.md`

## Limited primitive

Folder:

```text
03_byovd\04_limited-primitives
```

Drivers/writeups:

- `ASIO3_PREVIOUSMODE_DEEP_DIVE.md`

## MSR / multi-primitive

Folder:

```text
03_byovd\05_msr-and-multi-primitive
```

Drivers/writeups:

- `WINRING0_AWESOME_MINER_MSR_DEEP_DIVE.md`
- `GDRV_GIGABYTE_DEEP_DIVE.md`

## Workflow

Folder:

```text
03_byovd\99_workflow
```

Files:

- `NEW_DRIVER_REVERSING_WORKFLOW.md`

## Local source reference

Code snapshot/checkouts nam o:

```text
90_sources\_source\BYOVD
```
