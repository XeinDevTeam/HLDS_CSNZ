#ifndef IENGINE_H
#define IENGINE_H

#ifdef _WIN32
#pragma once
#endif

#include "interface.h"

enum
{
	ENGINE_RESULT_NONE,
	ENGINE_RESULT_RESTART,
	ENGINE_RESULT_UNSUPPORTEDVIDEO
};

class IEngine : public IBaseInterface
{
public:
	virtual int Run(HINSTANCE instance, char *basedir, const char *cmdline, char *szCommand, CreateInterfaceFn launcherFactory, CreateInterfaceFn filesystemFactory);
};

#define VENGINE_LAUNCHER_API_VERSION "VENGINE_LAUNCHER_API_VERSION002"

class CEngine : public IBaseInterface {
public:
    virtual BOOL Load(BOOL dedicated, char* basedir, char* cmdline);
    virtual void Unload();
    virtual void SetState(int state);
    virtual void GetState();
    virtual void SetSubState();
    virtual void GetSubState();
    virtual void Frame();
    virtual void GetFrameTime();
    virtual void GetCurTime();
    virtual void TrapKey_Event(int key, bool down);
    virtual void TrapMouse_Event();
    virtual void StartTrapMode();
    virtual bool IsTrapping();
    virtual void CheckDoneTrapping();
    virtual int  GetQuitting();
    virtual void SetQuitting(int quitType);

public:
    int m_nQuitting;
    int m_nDLLState;
    int m_nSubState;
    double m_fCurTime;
    double m_fFrameTime;
    double m_fOldTime;
    char m_bTrapMode;
    char m_bDoneTrapping;
    short unk5;
    int m_nTrapKey;
    int m_nTrapButtons;
    int undef3;
};

extern CEngine* engine;

#endif