# Build Instructions

## Requirements
- Visual Studio 2019/2022 with "Desktop development with C++" workload
- Windows SDK 10.0.19041+
- Windows Driver Kit (WDK 10) — for kernel/ subdirectory only
- WinDivert 2.x package — for 16_windivert_edrprison.c only (download separately)

## User-mode programs (all .c files in this folder)

```cmd
:: Open "x64 Native Tools Command Prompt for VS 2022" then:
cl.exe /W3 /O2 /D_UNICODE /DUNICODE <file>.c /link <libs>
```

## Per-file build commands

```cmd
:: 01_wfp_block.c
cl 01_wfp_block.c /link fwpuclnt.lib rpcrt4.lib Advapi32.lib

:: 02_wfp_delete.c
cl 02_wfp_delete.c /link fwpuclnt.lib rpcrt4.lib

:: 03_360wfp_exploit.c
cl 03_360wfp_exploit.c

:: 04_qos_throttle.c
cl 04_qos_throttle.c /link Advapi32.lib rpcrt4.lib

:: 05_nrpt_sinkhole.c
cl 05_nrpt_sinkhole.c /link Advapi32.lib rpcrt4.lib

:: 06_ipsec_block.c
cl 06_ipsec_block.c /link Advapi32.lib

:: 07_null_route.c
cl 07_null_route.c /link iphlpapi.lib ws2_32.lib

:: 08_ip_sinkhole.c
cl 08_ip_sinkhole.c /link iphlpapi.lib ws2_32.lib

:: 09_winhttp_proxy.c
cl 09_winhttp_proxy.c /link Advapi32.lib

:: 10_tcp_rst.c
cl 10_tcp_rst.c /link iphlpapi.lib ws2_32.lib

:: 11_cert_store.c
cl 11_cert_store.c /link Crypt32.lib Advapi32.lib

:: 12_bfe_stop.c
cl 12_bfe_stop.c /link Advapi32.lib

:: 13_handle_theft.c
cl 13_handle_theft.c

:: 14_cpu_starve.c
cl 14_cpu_starve.c

:: 15_pipe_hijack.c
cl 15_pipe_hijack.c

:: 16_windivert_edrprison.c
:: Requires WinDivert 2.x — download from https://reqrypt.org/windivert.html
:: Place WinDivert.h and WinDivert.lib in the same folder, then:
cl 16_windivert_edrprison.c /I. /link WinDivert.lib
:: At runtime: WinDivert64.sys must be in same directory as .exe

:: 17_hosts_poison.c
cl 17_hosts_poison.c

:: 18_winsock_lsp_install.c  (installer EXE — installs the DLL into Winsock catalog)
cl 18_winsock_lsp_install.c /link ws2_32.lib Rpcrt4.lib

:: 18_winsock_lsp_dll.c  (the LSP DLL itself — compile as DLL)
cl /LD 18_winsock_lsp_dll.c /link ws2_32.lib /OUT:18_winsock_lsp_dll.dll
:: Usage: 18_winsock_lsp_install.exe install 18_winsock_lsp_dll.dll

:: 19_adapter_binding.c
cl 19_adapter_binding.c /link Advapi32.lib iphlpapi.lib

:: 20_firewall_profile.c
cl 20_firewall_profile.c /link Advapi32.lib
```

## Kernel drivers (kernel/ subfolder)

All kernel drivers require WDK 10 and Visual Studio with kernel driver support.
Enable test-signing before loading: `bcdedit /set testsigning on` + reboot.

```cmd
:: WFP Callout Driver
cd kernel\wfp_callout
msbuild wfp_callout.vcxproj /p:Configuration=Release /p:Platform=x64
:: Load:
sc create WfpCallout type= kernel start= demand binpath= "%cd%\x64\Release\wfp_callout.sys"
sc start WfpCallout
sc stop WfpCallout && sc delete WfpCallout

:: NDIS Lightweight Filter Driver
cd kernel\ndis_lwf
msbuild ndis_lwf.vcxproj /p:Configuration=Release /p:Platform=x64
:: Install via INF (requires PnP install):
pnputil /add-driver ndis_lwf.inf /install

:: IRP Hook Driver
cd kernel\irp_hook
msbuild irp_hook.vcxproj /p:Configuration=Release /p:Platform=x64
:: Load:
sc create IrpHook type= kernel start= demand binpath= "%cd%\x64\Release\irp_hook.sys"
sc start IrpHook
sc stop IrpHook && sc delete IrpHook
```

## Running (requires Administrator)

All user-mode programs require Administrator privileges.
Kernel drivers require Administrator + test signing mode or DSE bypass.

## Technique-to-File Mapping

| Code File                    | Technique / Doc File                          |
|------------------------------|-----------------------------------------------|
| 01_wfp_block.c               | WFP filter injection (doc 02)                 |
| 02_wfp_delete.c              | WFP filter deletion (doc 03)                  |
| 03_360wfp_exploit.c          | BYOVD 360WFP exploit (doc 04)                 |
| 04_qos_throttle.c            | QoS throttling / EDRChoker (doc 06)           |
| 05_nrpt_sinkhole.c           | NRPT DNS sinkhole (Technique B)               |
| 06_ipsec_block.c             | IPSec filter rules (Technique C)              |
| 07_null_route.c              | Null routing / blackhole (Technique D)        |
| 08_ip_sinkhole.c             | IP sinkholing (Technique E)                   |
| 09_winhttp_proxy.c           | WinHTTP/MDE proxy poison (Technique F)        |
| 10_tcp_rst.c                 | TCP RST / SetTcpEntry (Technique H)           |
| 11_cert_store.c              | Certificate store manipulation (Technique I)  |
| 12_bfe_stop.c                | BFE service disruption (Technique J)          |
| 13_handle_theft.c            | Socket handle theft (Technique L)             |
| 14_cpu_starve.c              | CPU starvation (Technique M)                  |
| 15_pipe_hijack.c             | Named pipe interception (Technique P)         |
| 16_windivert_edrprison.c     | WinDivert EDRPrison (doc 05)                  |
| 17_hosts_poison.c            | Hosts file poisoning (Technique A)            |
| 18_winsock_lsp_install.c     | Winsock LSP installer (Technique G)           |
| 18_winsock_lsp_dll.c         | Winsock LSP DLL (Technique G — compile as DLL)|
| 19_adapter_binding.c         | Adapter binding manipulation (Technique N)    |
| 20_firewall_profile.c        | Firewall profile switching (Technique O)      |
| kernel/wfp_callout/          | Custom WFP callout driver (doc 07)            |
| kernel/ndis_lwf/             | NDIS LWF packet drop driver (Technique K)     |
| kernel/irp_hook/             | IRP dispatch table hook (Technique Q)         |
