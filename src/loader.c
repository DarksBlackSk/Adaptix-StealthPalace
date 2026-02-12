#include <windows.h>
#include "tcg.h"

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc ( LPVOID, SIZE_T, DWORD, DWORD );

char _DLL_ [0] __attribute__ ( ( section ( "dll" ) ) );

#define GETRESOURCE(x) ( char * ) &x

void go ( )
{
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = LoadLibraryA;
    funcs.GetProcAddress = GetProcAddress;

    char * dll_src = GETRESOURCE ( _DLL_ );
    DLLDATA dll_data;
    ParseDLL ( dll_src, &dll_data );

    char * dll_dst = KERNEL32$VirtualAlloc ( NULL, SizeOfDLL ( &dll_data ), MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE );

    LoadDLL ( &dll_data, dll_src, dll_dst );
    ProcessImports ( &funcs, &dll_data, dll_dst );

    DLLMAIN_FUNC entry_point = EntryPoint ( &dll_data, dll_dst );
    entry_point ( ( HINSTANCE ) dll_dst, DLL_PROCESS_ATTACH, NULL );

    /* * THE TRICK: Stack Strings
     * We declare the string as a char array. This forces the compiler 
     * to build the string byte-by-byte on the stack at runtime.
     * This avoids the "Relocation" error completely.
     */
    char targetFunc[] = { 'G','e','t','V','e','r','s','i','o','n','s', 0 };

    typedef void (WINAPI * _GetVersions)();
    _GetVersions pGetVersions = (_GetVersions)GetExportAddress(dll_dst, targetFunc);

    if (pGetVersions != NULL) {
        pGetVersions(); 
    }
}

FARPROC resolve ( DWORD mod_hash, DWORD func_hash )
{
    HANDLE module = findModuleByHash ( mod_hash );
    return findFunctionByHash ( module, func_hash );
}