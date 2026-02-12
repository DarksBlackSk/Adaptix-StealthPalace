void* GetExportAddress(char* base, const char* targetName) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* names = (DWORD*)(base + exports->AddressOfNames);
    DWORD* functions = (DWORD*)(base + exports->AddressOfFunctions);
    WORD* ordinals = (WORD*)(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* currentName = (char*)(base + names[i]);
        
        /* Manual String Compare */
        const char* s1 = currentName;
        const char* s2 = targetName;
        int match = 1;
        
        while (*s1 && *s2) {
            if (*s1 != *s2) {
                match = 0;
                break;
            }
            s1++;
            s2++;
        }
        if (match && *s1 == *s2) { /* Ensure both ended at null terminator */
             return (void*)(base + functions[ordinals[i]]);
        }
    }
    return NULL;
}