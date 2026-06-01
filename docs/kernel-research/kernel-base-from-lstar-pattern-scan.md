# Kernel Base Discovery from `MSR_LSTAR` and PE Header Scanning

## Purpose

This note explains a common Windows x64 kernel research pattern:

```text
find a trusted pointer inside ntoskrnl
  -> walk backward through kernel virtual memory
  -> identify the PE image header
  -> recover the loaded kernel image base
```

The concrete example is `MSR_LSTAR`, which normally points at the 64-bit syscall entry path in `ntoskrnl.exe`. This is a research and debugging concept document, not an exploit chain.

## Short Version

On x64 Windows:

```text
IA32_LSTAR MSR
  -> kernel VA of the 64-bit syscall entry
  -> address is inside ntoskrnl.exe
  -> align down to a page boundary
  -> scan backward by pages
  -> find valid MZ + PE headers
  -> validate that LSTAR is inside that image range
  -> result is ntoskrnl base
```

Mental model:

```text
ntoskrnl base                      LSTAR / syscall entry
fffff806`49e00000                  fffff806`4a23c400
|----------------------------------|
MZ ... PE ... .text ... KiSystemCall64-ish code
```

`LSTAR` is not the kernel base. It is a pointer somewhere inside the kernel image. The PE scan turns an interior pointer into the containing module base.

## Background: Why This Works

### KASLR

Kernel Address Space Layout Randomization means `ntoskrnl.exe` is not loaded at the same virtual address every boot.

Example:

```text
boot 1: nt base = fffff800`2c000000
boot 2: nt base = fffff806`49e00000
```

But once the kernel is loaded, code inside `ntoskrnl` still lives at:

```text
runtime VA = runtime nt base + RVA inside image
```

So if a researcher can identify any reliable runtime VA inside `ntoskrnl`, the remaining task is to find the beginning of the PE image that contains it.

### PE Image Layout

Windows kernel images are Portable Executable images mapped into memory. A loaded PE image begins with a DOS header:

```text
MZ
```

The DOS header contains `e_lfanew` at offset `0x3c`. `e_lfanew` points to the NT headers:

```text
PE\0\0
```

Simplified:

```text
base
  +0x00  IMAGE_DOS_HEADER.e_magic == "MZ"
  +0x3c  IMAGE_DOS_HEADER.e_lfanew
  +e_lfanew IMAGE_NT_HEADERS.Signature == "PE\0\0"
```

Because the image base is page-aligned, scanning backward by `0x1000` pages from a known code pointer is enough to find candidate image starts.

## What `MSR_LSTAR` Gives You

On x64 CPUs, the `IA32_LSTAR` model-specific register controls the target RIP for 64-bit `syscall` transitions.

Register:

```text
IA32_LSTAR = 0xC0000082
```

Conceptually:

```text
usermode syscall instruction
  -> CPU reads IA32_LSTAR
  -> CPU transfers execution to kernel RIP stored in LSTAR
  -> Windows syscall entry path handles the transition
```

On Windows, this target is inside the kernel syscall entry code. Depending on build and symbol naming, the nearest public symbol may look like `KiSystemCall64`, `KiSystemCall64Shadow`, or another syscall-entry-adjacent label.

Important point:

```text
LSTAR is a pointer into ntoskrnl .text.
```

That makes it a good anchor for finding `ntoskrnl` base in a debugger or authorized lab setting.

## Full Conceptual Algorithm

Given:

```text
lstar = runtime value of IA32_LSTAR
```

Algorithm:

```text
candidate = align_down(lstar, 0x1000)

while candidate is still in plausible kernel VA range:
    if memory at candidate begins with "MZ":
        read e_lfanew from candidate + 0x3c

        if e_lfanew is sane:
            nt_header = candidate + e_lfanew

            if nt_header begins with "PE\0\0":
                validate PE headers

                if candidate <= lstar < candidate + SizeOfImage:
                    return candidate as ntoskrnl base

    candidate -= 0x1000
```

The scan direction is backward because `LSTAR` points into code after the image base.

## Validation Rules

Do not trust only `MZ`. Random memory can contain those bytes.

A strong validation checklist:

| Check | Expected value / idea | Why it matters |
|---|---|---|
| DOS magic | `MZ` | Candidate looks like PE start |
| `e_lfanew` | Positive, reasonably small | Avoid bogus pointer into unrelated memory |
| NT signature | `PE\0\0` | Confirms NT headers |
| Machine | `IMAGE_FILE_MACHINE_AMD64`, `0x8664` | Confirms x64 image |
| Optional header magic | `IMAGE_NT_OPTIONAL_HDR64_MAGIC`, `0x20b` | Confirms PE32+ |
| Section count | Reasonable | Avoid malformed header |
| `SizeOfImage` | Reasonable kernel image size | Defines loaded image range |
| Range check | `base <= LSTAR < base + SizeOfImage` | Proves LSTAR belongs to this image |
| Section check | LSTAR lands in executable section | Stronger proof it is in kernel text |

Minimal validation:

```text
MZ
  -> sane e_lfanew
  -> PE\0\0
  -> AMD64
  -> PE32+
  -> LSTAR inside SizeOfImage
```

Better validation also parses the section table and verifies that `LSTAR` lies inside a section such as `.text` or another executable code section.

## Pattern Scan vs Header Scan

People often say "pattern scan" for two related but different techniques.

### 1. Header scan

This is the technique in this document:

```text
known pointer inside module
  -> scan backward
  -> find MZ / PE image header
  -> recover module base
```

This is relatively robust because PE headers have a stable format.

### 2. Byte signature scan

This means:

```text
known module base
  -> parse .text or another section
  -> search for bytes matching a function or instruction sequence
  -> recover private function/global location
```

This is much more fragile because compiler output and kernel code change across builds and cumulative updates.

For the question "`KiSystemCall64` to kernel base", the core technique is header scanning, not byte signature scanning.

## Where `KiSystemCall64` Fits

Public discussions often say:

```text
read LSTAR -> get KiSystemCall64 -> scan back to nt base
```

This is a useful shortcut, but technically:

- `LSTAR` gives the syscall entry address.
- The nearest symbol may not be exactly named `KiSystemCall64` on every build.
- KPTI/KVA shadow and syscall-entry changes can affect naming and nearby code.
- The important invariant is not the symbol name; it is that the address is inside `ntoskrnl`.

Better wording:

```text
read LSTAR -> get a syscall-entry pointer inside ntoskrnl -> scan back to nt base
```

## WinDbg-Oriented Learning Flow

In a kernel debugging lab, the learning flow is:

```text
1. Inspect loaded modules.
2. Observe ntoskrnl base.
3. Read or inspect the syscall entry pointer.
4. Resolve nearest symbol.
5. Manually reason backward to the PE header.
6. Confirm that the result matches the debugger's module list.
```

Useful conceptual debugger checks:

```text
lm m nt
```

Shows the loaded range of the `nt` module.

```text
ln <lstar_address>
```

Resolves the nearest symbol to the syscall-entry address.

```text
db <candidate_base> L2
```

Checks whether the candidate begins with `MZ`.

```text
dd <candidate_base>+3c L1
```

Reads `e_lfanew`.

```text
db <candidate_base>+<e_lfanew> L4
```

Checks for `PE\0\0`.

The point is not memorizing commands. The point is learning to prove:

```text
this pointer is inside this mapped PE image
```

## Failure Modes

### Reading unmapped memory

If the scanner blindly dereferences every page while walking backward, it can fault. Real code needs safe memory-read behavior, exception handling, or a trusted debugger/kernel context.

### False `MZ`

Checking only two bytes is weak. Always validate the NT header and image range.

### Wrong containing module

If the anchor pointer is not actually inside `ntoskrnl`, the scan may recover another loaded driver. The range check tells you the containing image, not necessarily `nt`.

### Build-specific assumptions

The syscall-entry symbol name and layout can differ by Windows build. Do not hardcode one symbol name as a universal fact.

### KPTI and shadow paths

KPTI/KVA shadow changed parts of the syscall transition design. The broad idea remains useful, but code paths and symbol naming can vary.

### Virtualization and security products

Hypervisors, EDRs, and instrumentation can alter what is visible or how the transition path is monitored. Treat lab observations as build- and configuration-specific.

## Defensive and Research Uses

Legitimate uses:

- validating kernel module layout in a debugger,
- teaching KASLR and PE mapping concepts,
- checking whether an address belongs to `ntoskrnl` or a driver,
- crash-dump triage,
- verifying symbol and module-list consistency,
- understanding how public research derives base addresses from interior pointers.

Risky or out-of-scope uses:

- building an exploit chain around a kernel pointer leak,
- publishing reusable bypass code,
- hardcoding offsets or signatures for live targets,
- combining this with arbitrary kernel read/write to modify security state.

## Comparison With Other Kernel Base Discovery Methods

| Method | Basic idea | Notes |
|---|---|---|
| `MSR_LSTAR` anchor | Syscall entry pointer lies inside `ntoskrnl` | Strong conceptual anchor in kernel/debug context |
| System module query | Ask OS for loaded module list | Availability and disclosure behavior can vary by policy/version |
| `PsLoadedModuleList` | Walk kernel module list | Requires kernel read or debugger |
| IDT/GDT anchors | Use interrupt or descriptor-related kernel pointers | More architecture-specific |
| Known exported symbol | Resolve export and subtract RVA | Requires module/symbol knowledge |
| Crash dump module list | Use dump metadata | Great for offline triage |

## Study Checklist

You understand this technique when you can answer:

- What does `IA32_LSTAR` store?
- Why is the `LSTAR` value inside `ntoskrnl`?
- Why is scanning backward page-by-page reasonable?
- What are `MZ`, `e_lfanew`, and `PE\0\0`?
- Why is `MZ` alone insufficient?
- How does `SizeOfImage` validate that `LSTAR` belongs to the candidate image?
- Why does KASLR make this technique useful?
- Why are byte signatures more fragile than PE header scanning?

## Summary

The essential idea:

```text
MSR_LSTAR gives a stable runtime pointer into the Windows syscall entry path.
That pointer is inside ntoskrnl.
ntoskrnl is a PE image in memory.
The PE image starts at a page-aligned MZ/PE header.
Scanning backward from LSTAR and validating PE headers recovers ntoskrnl base.
```

Do not think of this as magic. It is just containment:

```text
given an address inside a mapped image,
find the start of the mapped image.
```

## References

- Microsoft PE format:
  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Intel SDM context for `IA32_LSTAR` and `SYSCALL`:
  https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- Existing repo note, `docs/kernel-research/kernel-object-layout-drift.md`
- Existing repo note, `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md`
