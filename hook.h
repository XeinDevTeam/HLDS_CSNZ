#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include <Windows.h>

typedef float vec_t;
typedef float vec2_t[2];
typedef float vec3_t[3];
typedef int (*pfnUserMsgHook)(const char* pszName, int iSize, void* pbuf);

#include <wrect.h>
#include <cdll_int.h>

void Hook(HMODULE hModule);
void Unhook();

extern cl_enginefunc_t* g_pEngine;

#define CreateHook(funcType, returnType, funcName, ...) \
returnType (funcType* g_pfn##funcName)(__VA_ARGS__); \
returnType funcType Hook_##funcName(__VA_ARGS__)

#define CreateHookClassType(returnType,funcName,classType, ...) \
returnType (__thiscall* g_pfn##funcName)(classType*ptr, __VA_ARGS__); \
returnType __fastcall Hook_##funcName(classType*ptr, int reg, __VA_ARGS__)

#define CreateHookClass(returnType, funcName, ...) CreateHookClassType(returnType, funcName, void, __VA_ARGS__)

#define ExternHook(funcType, returnType, funcName, ...) \
extern returnType (funcType* g_pfn##funcName)(__VA_ARGS__); \
extern returnType funcType Hook_##funcName(__VA_ARGS__);

#define ExternHookClassType(returnType,funcName,classType, ...) \
extern returnType (__thiscall* g_pfn##funcName)(classType*ptr, __VA_ARGS__); \
extern returnType __fastcall Hook_##funcName(classType*ptr, int reg, __VA_ARGS__);

extern int* ptrIsDedicated;
extern int* ptrgiActive;
extern int* ptrDediExports;

ExternHook(__cdecl, void, Sys_InitArgv, char* szCmd);
ExternHook(__cdecl, BOOL, FileSystem_Init, const char* szBaseDir, void* fn);
ExternHook(__cdecl, void, CBuf_AddText, char* text);
ExternHook(__cdecl, void, InitSocketManager, char* szFileName, char a2, char a3);
ExternHook(__cdecl, void, SV_UpdateStatus, float* fps, int* nActive, int* nNotUsed, int* nMaxPlayers, char* pszMap);

class CSocketManager {
public:
    virtual ~CSocketManager();

    void SetHWND(HWND hHWND) {
        windowHandle = hHWND;
    }

private:
    struct CSocket* socket;
    int unk2;
    HWND windowHandle;
    struct Packet* packetFunction[0x100];
    int unk10;
    char encrypt;
    char unk6;
    int unk7;
    int unk8;
    void* unk9; // some holder
    void* log;
    CRITICAL_SECTION critical;
};

extern CSocketManager* gSocketManager;
