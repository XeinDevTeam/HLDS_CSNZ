#include <Windows.h>

#include "IEngine.h"
#include "IRegistry.h"
#include "IDedicatedServerAPI.h"
#include "IGame.h"

#include "hook.h"
#include <stdio.h>
#include <ctime>

CRegistry* registry;

CDedicatedServerAPI* engineAPI = new CDedicatedServerAPI();
CEngine* engine;
CGame* game;

CSocketManager* gSocketManager;

int* ptrIsDedicated;
int* ptrgiActive;
int* ptrDediExports;

// Legacy_Sys_Printf
// 55 8B EC 81 EC 04 04 00 00 A1 ? ? ? ? 33 C5 89 45 ? 8D 45 ? 50 6A 00 FF 75 ? 8D 85 ? ? ? ? 68 00 04 00 00 50 E8 ? ? ? ? 8B 08 FF 70 ? 83 C9 01 51 FF 15 ? ? ? ? 8B 0D
// mov ecx, dediExports
// 8B 0D ? ? ? ? 83 C4 1C 85 C9

// Sys_InitArgv
// 55 8B EC A1 ? ? ? ? BA 01 00 00 00
// \x55\x8B\xEC\xA1\x00\x00\x00\x00\xBA\x01\x00\x00\x00 xxxx????xxxxx

// Engine::InitGame(init, encrypted)
// mov ecx, engine
// 8B 0D ? ? ? ? A3 ? ? ? ? A1 ? ? ? ? A3
// move ecx, registry
// 8B 0D ? ? ? ? 8B 01 FF 10 E8 ? ? ? ? 8B C8

// Sys_InitGame
// mov bIsDedicated, eax
// A3 ? ? ? ? E8 ? ? ? ? 6A 00 68 B4 4A A3 02

// FileSystem_Init
// 55 8B EC 8B 4D ? BA B0 BE FE 02

// giActive
// \xC7\x05\x00\x00\x00\x00\x00\x00\x00\x00\xC7\x05\x00\x00\x00\x00\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x84\xC0 xx????????xx????????x????xx

void SetHWND(HWND hHwnd)
{
    
}

extern int g_iPort;
bool CDedicatedServerAPI::Init(const char* basedir, const char* cmdline, CreateInterfaceFn launcherFactory, CreateInterfaceFn filesystemFactory) {

    // TODO: implement dedicated exports(but just printf exported... so direct hook more better)

    strncpy_s(this->m_OrigCmd, cmdline, ARRAYSIZE(this->m_OrigCmd));
    this->m_OrigCmd[ARRAYSIZE(this->m_OrigCmd) - 1] = 0;

    printf("[Trace] Sys_InitArgv\n");
    g_pfnSys_InitArgv(this->m_OrigCmd);

    engine->SetQuitting(0);
    registry->Init();

    *ptrIsDedicated = true;

    printf("[Trace] FileSystem_Init\n");
    if (!g_pfnFileSystem_Init(basedir, filesystemFactory))
        return false;

    printf("[Trace] InitSocketManager\n");
    time_t currentTime = time(NULL);
    tm* currentLocalTime = localtime(&currentTime);
    int currentProcessId = GetCurrentProcessId();
    snprintf(this->szLogFormat, sizeof(this->szLogFormat), "csods_%04d%02d%02d_%02d%02d%02d_%u_%d",
        currentLocalTime->tm_year + 1900,
        currentLocalTime->tm_mon + 1,
        currentLocalTime->tm_mday,
        currentLocalTime->tm_hour,
        currentLocalTime->tm_min,
        currentLocalTime->tm_sec,
        currentProcessId,
        g_iPort);
    sprintf(this->szLogPath, "%s.log", this->szLogFormat);
    g_pfnInitSocketManager(this->szLogPath, 0, 0);

    printf("[Trace] game->InitCSONMWrapper\n");
    game->InitCSONMWrapper();

    gSocketManager->SetHWND(game->GetMainWindow());

    printf("[Trace] engine->Load\n");
    char szCopy1[260];
    char szCopy2[260];

    strcpy_s(szCopy1, basedir);
    strcpy_s(szCopy2, cmdline);

    if (!engine->Load(1, szCopy1, szCopy2))
        return false;

    Hook_CBuf_AddText("exec server.cfg\n");

    return 1;
}

int CDedicatedServerAPI::Shutdown() {
    engine->Unload();
    game->ShutdownGameWindow();
    registry->Shutdown();

    return true;
}

bool CDedicatedServerAPI::RunFrame() {
    if (engine->GetQuitting())
        return false;

    engine->Frame();
    return true;
}

void CDedicatedServerAPI::AddConsoleText(char* text) {
    Hook_CBuf_AddText(text);
}

void CDedicatedServerAPI::UpdateStatus(float* fps, int* nActive, int* nMaxPlayers, char* pszMap) {
    Hook_SV_UpdateStatus(fps, nActive, 0, nMaxPlayers, pszMap);
}
