# Windows Kernel Exploit Research Resource

Thu muc nay duoc sap xep theo lo trinh hoc va theo primitive khai thac.

## Cach doc nhanh

1. Bat dau voi `01_core-handbook`.
2. Doc `02_mitigations-vbs-hvci-vtrp` de nam VBS, HVCI, kCFG, VT-rp, HLAT.
3. Sang `03_byovd\00_index-and-matrix` de xem ban do driver va primitive.
4. Chon tung nhom trong `03_byovd` theo primitive can hoc.
5. Khi can doi chieu code goc, xem `90_sources`.

## Cau truc

```text
E:\Windows-kernel-exploit-research-resource
|-- README.md
|-- MEMORY.md
|-- 01_core-handbook
|   `-- WINDOWS_KERNEL_EXPLOIT_RESEARCH.md
|-- 02_mitigations-vbs-hvci-vtrp
|   |-- VT_RP_HLAT_DEEP_DIVE_VI.md
|   |-- CONNOR_HVCI_KCFG_DEEP_DIVE_VI.md
|   |-- MITIGATION_MATRIX.md
|   `-- RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md
|-- 03_byovd
|   |-- 00_index-and-matrix
|   |-- 01_physical-memory-rw
|   |-- 02_virtual-kernel-rw
|   |-- 03_process-kill
|   |-- 04_limited-primitives
|   |-- 05_msr-and-multi-primitive
|   `-- 99_workflow
|-- 04_connor-mcgarr-study
|-- 05_global-research-map
`-- 90_sources
    `-- _source
```

## Noi dung chinh

- `01_core-handbook`: handbook tong quan ve Windows kernel exploit, mitigation timeline, EPROCESS offsets, primitive taxonomy va roadmap.
- `02_mitigations-vbs-hvci-vtrp`: deep-dive ve VBS/HVCI/kCFG/VT-rp/HLAT, ma tran mitigation, va chien luoc khi co R/W primitive.
- `03_byovd\00_index-and-matrix`: index BYOVD, primitive matrix, danh sach writeup gan day.
- `03_byovd\01_physical-memory-rw`: ASTRA64, Lenovo LnvMSRIO, ThrottleStop, eneio64, PowerStrip.
- `03_byovd\02_virtual-kernel-rw`: RTCore64, Dell dbutil, Qihoo DsArk64.
- `03_byovd\03_process-kill`: K7RKScan, BdApiUtil64, TfSysMon, Zemana/Terminator.
- `03_byovd\04_limited-primitives`: AsIO3 `PreviousMode`.
- `03_byovd\05_msr-and-multi-primitive`: WinRing0/Awesome Miner, Gigabyte gdrv.
- `03_byovd\99_workflow`: workflow reverse driver moi.
- `04_connor-mcgarr-study`: deep-research theo cac bai Windows internals/exploit cua Connor McGarr.
- `05_global-research-map`: ban do nguon quoc te theo quoc gia/khu vuc, lab, vendor, campaign va technique.
- `90_sources`: checkout/source snapshot dung de viet walkthrough.

## File dieu huong

`MEMORY.md` la file nho trang thai research: da co gi, source nao da dung, ket luan quan trong va viec nen lam tiep.
