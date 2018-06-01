#include "mod.h"
#include <windows.h>

#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>

typedef uint8_t u8;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef float f32;
typedef double f64;

#define DATA_LOG_FILE_PATH "data_log.txt"

typedef NTSTATUS (NTAPI *Proc_NtResumeProcess)(HANDLE);
Proc_NtResumeProcess NtResumeProcess = NULL;

HMODULE hDllModule;
HMODULE hDataExe;
HMODULE hDarksoulsExe;
HMODULE hDinput8;
HWND hGameWindow;

void* orgn_requestLoadFile = nullptr;

i64 performanceFrequency;
i64 startCounter;

FILE* logFile;

void initTime()
{
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    startCounter = (i64)li.QuadPart;
    QueryPerformanceFrequency(&li);
    performanceFrequency = (i64)li.QuadPart / 1000;
}

// milliseconds
i64 getTimeSinceStart()
{
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return ((i64)li.QuadPart - startCounter) / performanceFrequency;
}

void logf(const char* format, ...)
{
    char buffer[4096];
    char format2[1024];

    DWORD thid = GetCurrentThreadId();
    i64 t = getTimeSinceStart();
    i32 milli = t % 1000;
    i32 sec = (t / 1000) % 60;
    i32 minu = t / 60000;
    sprintf(format2, "[thd_%05x|%03d:%02d:%04d] %s\n", thid, minu, sec, milli, format);

    va_list args;
    va_start(args, format);
    const i32 buffLen = vsprintf(buffer, format2, args);
    va_end(args);

    printf(buffer);
    fwrite(buffer, buffLen, 1, logFile);
}

void resumeGameThreads()
{
    logf("Resuming all threads...");

    DWORD ownPID  = GetCurrentProcessId();
    DWORD ownThid  = GetCurrentThreadId();
    i32 atLeastOne = 0;

    while(atLeastOne == 0) {
        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        THREADENTRY32 threadEntry;
        threadEntry.dwSize = sizeof(THREADENTRY32);

        if(Thread32First(hThreadSnapshot, &threadEntry)) {
            do {
                if(threadEntry.th32OwnerProcessID == ownPID && threadEntry.th32ThreadID != ownThid) {

                    HANDLE hThd = OpenThread(THREAD_ALL_ACCESS, FALSE,
                                             threadEntry.th32ThreadID);
                    ResumeThread(hThd);
                    atLeastOne++;
                }
            } while(Thread32Next(hThreadSnapshot, &threadEntry));
        }
    }

    logf("threads resumed");
}

#if 0
void changeTitle()
{
    char title[256];
    sprintf(title, "DARKSOULS :: Mod by LordSk [%s]", MODDLL_VERSION);
    SetWindowTextA(hGameWindow, title);
}

HWND WINAPI patched_CreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName,
                                    DWORD dwStyle, int X, int Y, int nWidth, int nHeight,
                                    HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
    hGameWindow = CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight,
                                  hWndParent, hMenu, hInstance, lpParam);
    changeTitle();
    return hGameWindow;
}

void STDCALL logLoadedFile(wchar_t* filename)
{
    logf("load_file(%ls)", filename);
}

NAKED void patched_loadFileUniversal()
{
    PUSH_REGISTERS()

    __asm {
        push eax
        call logLoadedFile
    }

    POP_REGISTERS()

    // original function code
    // jump back
    __asm {
        push ebp
        push esi
        mov esi,ecx
        test byte ptr ds:[esi+22],2
        jmp loadFileUniversal_jmpBack
    }
}

void STDCALL logDLThreadCreate(const char* threadName)
{
    logf("DLThreadCreate(%s)", threadName);
}

NAKED void patched_DLThreadCreate()
{
    PUSH_REGISTERS()

    __asm {
        push [esp+0x28]
        call logDLThreadCreate
    }

    POP_REGISTERS()

    // original function code
    // jump back
    __asm {
        push 0xffffffff
        push 0x10533b1
        jmp DLThreadCreate_jmpBack
    }
}

void STDCALL logDbgPrint(const char* msg, i32 i, const char* srcFile)
{
    logf("dbg_print(%s, %d, %s)", msg, i, srcFile);
}

NAKED void patched_dbgPrint()
{
    PUSH_REGISTERS()

    __asm {
        push [esp+0x24]
        push [esp+0x2C]
        push [esp+0x34]
        call logDbgPrint
    }

    POP_REGISTERS()

    // original function code
    // jump back
    __asm {
        mov ecx, dword ptr [esp + 4]
        push edi
        mov edi, dword ptr [esp + 0x10]
        jmp dbgPrint_jmpBack
    }
}

void STDCALL logSetupLuaFunction(const char* funcName, void* funcpp)
{
    logf("setup_lua_function(%s, %#x)", funcName, (u32)**(u32**)funcpp);
}

NAKED void patched_setupLuaFunction()
{
    PUSH_REGISTERS()

    __asm {
        push [esp+0x1C]
        push [esp+0x24]
        call logSetupLuaFunction
    }

    POP_REGISTERS()

    // original function code
    // jump back
    __asm {
        push esi
        push edi
        mov edi, dword ptr [esp + 0x10]
        jmp setupLuaFunction_jmpBack
    }
}


HRESULT WINAPI patched_DirectInput8Create(HINSTANCE hinst, DWORD dwVersion, REFIID riidltf,
                                          LPVOID *ppvOut, LPUNKNOWN punkOuter)
{
    logf("DirectInput8Create(ppvOut=%#x)", (u32)ppvOut);
    HRESULT r = myDirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
    return r;
}

void STDCALL myWndProc(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if(uMsg == WM_KEYUP) {
        u32 vkCode = (u32)wParam;

        //logf("key_up=%d", vkCode);

        switch(vkCode) {
            case 0x4C: // L
            logf("GetLevel()=%d", dsi.GetLevel());
            break;
        }
    }
}

NAKED void patched_windowProc()
{
    PUSH_REGISTERS()

    __asm {
        push [esp+0x28]
        push [esp+0x28]
        push [esp+0x28]
        call myWndProc
    }

    POP_REGISTERS()

    // original function code
    // jump back
    __asm {
        push esi
        mov esi, dword ptr [esp + 0xc]
        cmp esi, 0x281
        jmp windowProc_jmpBack
    }
}

struct CreatureEntry
{
    char* namePtr;
    i32 type;
    i32 index;
    i32 model;
    void* ptr1;
    f32 x;
    f32 y;
    f32 z;
    f32 rx;
    f32 ry;
    f32 rz;
    f32 sx;
    f32 sy;
    f32 sz;
    u32 pad[11];
    char name[12];
    u32 pad2[14];
    i32 initParam;
    u32 pad3[9];
};

i32 cidCounter = 0;

void STDCALL hook_msb_parseCreatureEntry(void* entry)
{
    CreatureEntry& ce = *(CreatureEntry*)entry;
    logf("creature_entry(%s, pos={%.2f,%.2f,%.2f}, initparam=%d)", ce.namePtr,
         ce.x, ce.y, ce.z,
         ce.initParam);
#if 0
    // does nothing
    ce.sx = 2.f;
    ce.sy = 2.f;
    ce.sz = 2.f;
#endif

    //ce.type = 3; // crashes
    ce.model = 85;
    ce.initParam = -1;
    sprintf(ce.name, "c2790_%04d", cidCounter++);
}

NAKED void patched_msb_parseCreatureEntry()
{
    PUSH_REGISTERS()

    __asm {
        mov esi, dword ptr [edi + 0x164]
        mov esi, dword ptr [esi + ecx*4]
        push esi
        call hook_msb_parseCreatureEntry
    }

    POP_REGISTERS()

    // original function code
    // jump back
    __asm {
        push ebx
        push ebp
        push esi
        xor eax, eax
        xor esi, esi
        jmp msb_parseCreatureEntry_jmpBack
    }
}
#endif

/**
 * @brief patchCall
 * @param RVA (call [0x12345678])
 * @param myFuncAddr
 */
void patchCall(HMODULE hMod, u32 rva, u32 bytesToReplace, void* myFuncAddr)
{
    u32 call = 0xE8;
    u32 nop = 0x90;
    u32 relAddr = (u32)myFuncAddr - ((u32)hMod + rva) - 0x5;
    DWORD oldProt = 0;
    void* patchAddr = (void*)((u32)hMod + rva);
    if(VirtualProtect(patchAddr, 6, PAGE_READWRITE, &oldProt) == 0) {
        logf("VirtualProtect(%#x, 6) error=%d", (u32)patchAddr, GetLastError());
        return;
    }
    memset(patchAddr, call, 1);
    memcpy((void*)((u32)patchAddr + 0x1), &relAddr, 4);
    memset((void*)((u32)patchAddr + 0x5), nop, bytesToReplace-5);
    if(VirtualProtect(patchAddr, 6, oldProt, &oldProt) == 0) {
        logf("VirtualProtect(%#x, 6) error=%d", (u32)patchAddr, GetLastError());
        return;
    }
    logf("patchCall(rva=%#x addr_ptr=%#x addr_rel=%#x)", rva, (u32)&myFuncAddr,
           relAddr);
}

/**
 * @brief patchInlineHook needs 6 bytes
 * @param hMod
 * @param funcRva
 * @param bytesToReplace
 * @param myFuncAddr
 */
void patchInlineHook(HMODULE hMod, u32 funcRva, u32 bytesToReplace, void* myFuncAddr)
{
    u32 push = 0x68;
    u32 ret = 0xC3;
    u32 nop = 0x90;
    DWORD oldProt = 0;
    void* patchAddr = (void*)((u32)hMod + funcRva);
    u32 funcAddr = (u32)myFuncAddr;
    VirtualProtect(patchAddr, bytesToReplace, PAGE_READWRITE, &oldProt);

    memset(patchAddr, push, 1); // push
    memcpy((void*)((u32)patchAddr + 0x1), &funcAddr, 4); // addr
    memset((void*)((u32)patchAddr + 0x5), ret, 1); // ret
    memset((void*)((u32)patchAddr + 0x6), nop, bytesToReplace - 6); // nop

    VirtualProtect(patchAddr, bytesToReplace, oldProt, &oldProt);
    logf("patchInlineHook(rva=%#x addr_ptr=%#x bytesToReplace=%d)", funcRva, funcAddr,
           bytesToReplace);
}

void STDCALL _requestLoadFile(const wchar_t* filename)
{
    logf("loadFile(%ls)", filename);
}

void NAKED proxy_requestLoadFile()
{
    PUSH_REGISTERS();

    __asm {
        push [esi+4];
        call _requestLoadFile;
    }

    POP_REGISTERS();

    __asm {
        jmp orgn_requestLoadFile;
    }
}

void MOD_init()
{
    initTime();
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    setbuf(stdout, NULL);
    logFile = fopen(DATA_LOG_FILE_PATH, "w");

    logf("> MOD_init()");

    hDataExe = GetModuleHandleA("DARKSOULS.exe");
    if(hDataExe) {
        orgn_requestLoadFile = (void*)((u32)hDataExe + 0x8FC390);
        patchCall(hDataExe, 0x8FB428, 5, proxy_requestLoadFile);
    }

#if 0
    hDataExe = GetModuleHandleA("data.exe");
    if(hDataExe) {
        // change window name
        //patchCall(hDataExe, RVA_CREATE_MAIN_WINDOW_CALL, 0x6, patched_CreateWindowExW);

        loadFileUniversal_jmpBack = (void*)((u32)hDataExe + RVA_FILE_LOAD_UNIVERSAL +
                                            RVA_FILE_LOAD_UNIVERSAL_HOOKSIZE);
        patchInlineHook(hDataExe, RVA_FILE_LOAD_UNIVERSAL, RVA_FILE_LOAD_UNIVERSAL_HOOKSIZE,
                        patched_loadFileUniversal);

        DLThreadCreate_jmpBack = (void*)((u32)hDataExe + RVA_DLTHREAD_CREATE + RVA_DLTHREAD_CREATE_HOOKSIZE);
        patchInlineHook(hDataExe, RVA_DLTHREAD_CREATE, RVA_DLTHREAD_CREATE_HOOKSIZE, patched_DLThreadCreate);

        // never called
        /*dbgPrint_jmpBack = (void*)((u32)hDataExe + RVA_DBG_PRINT + RVA_DBG_PRINT_HOOK_SIZE);
        patchInlineHook(hDataExe, RVA_DBG_PRINT, RVA_DBG_PRINT_HOOK_SIZE, patched_dbgPrint);*/

        setupLuaFunction_jmpBack = (void*)((u32)hDataExe + RVA_SETUP_LUA_FUNCTION +
                                           RVA_SETUP_LUA_FUNCTION_HOOK_SIZE);
        patchInlineHook(hDataExe, RVA_SETUP_LUA_FUNCTION, RVA_SETUP_LUA_FUNCTION_HOOK_SIZE,
                        patched_setupLuaFunction);

        //patchCall(hDataExe, RVA_DIRECT_INPUT8_CREATE_CALL, 0x5, patched_DirectInput8Create);

        windowProc_jmpBack = (void*)((u32)hDataExe + RVA_WINDOW_PROC +
                                     RVA_WINDOW_PROC_HOOK_SIZE);
        patchInlineHook(hDataExe, RVA_WINDOW_PROC, RVA_WINDOW_PROC_HOOK_SIZE,
                        patched_windowProc);

        msb_parseCreatureEntry_jmpBack = (void*)((u32)hDataExe + RVA_MSB_PARSE_CREATURE_ENRTY +
                                     RVA_MSB_PARSE_CREATURE_ENRTY_HOOK_SIZE);
        patchInlineHook(hDataExe, RVA_MSB_PARSE_CREATURE_ENRTY, RVA_MSB_PARSE_CREATURE_ENRTY_HOOK_SIZE,
                        patched_msb_parseCreatureEntry);

        //setupDarksoulsFunctions();
    }
#endif

    HANDLE hProc = GetCurrentProcess();

#ifdef DBG_WAIT_FOR_ATTACH
    logf("Waiting for debugger to attach...");
    BOOL dbgPresent = FALSE;
    while(!dbgPresent && !IsDebuggerPresent()) {
        CheckRemoteDebuggerPresent(hProc, &dbgPresent);
        Sleep(10);
    }
#endif

    /*logf("Resuming process...");
    HMODULE hNtdll = GetModuleHandleA("ntdll");
    NtResumeProcess = (Proc_NtResumeProcess)GetProcAddress(hNtdll, "NtResumeProcess");
    if(NtResumeProcess) {
        NtResumeProcess(hProc);
    }*/
}

void MOD_deinit()
{
    fclose(logFile);
    FreeConsole();
}
