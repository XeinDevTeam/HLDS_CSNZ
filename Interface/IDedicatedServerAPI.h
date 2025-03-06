#pragma once

#include "interface.h"

class IDedicatedServerAPI : public IBaseInterface
{
public:
    virtual bool Init(const char* basedir, const char* cmdline, CreateInterfaceFn launcherFactory, CreateInterfaceFn filesystemFactory) = 0;
    virtual int Shutdown() = 0;
    virtual bool RunFrame() = 0;
    virtual void AddConsoleText(char* text) = 0;
    virtual void UpdateStatus(float* fps, int* nActive, int* nMaxPlayers, char* pszMap) = 0;
};

#define VENGINE_HLDS_API_VERSION "VENGINE_HLDS_API_VERSION002"

// custom

class CDedicatedServerAPI : IDedicatedServerAPI {
public:
    bool Init(const char* basedir, const char* cmdline, CreateInterfaceFn launcherFactory, CreateInterfaceFn filesystemFactory);
    int Shutdown();
    bool RunFrame();
    void AddConsoleText(char* text);
    void UpdateStatus(float* fps, int* nActive, int* nMaxPlayers, char* pszMap);

private:
    char m_OrigCmd[1024];
    char szLogPath[260];

public:
    char szLogFormat[260];
};

extern CDedicatedServerAPI* engineAPI;