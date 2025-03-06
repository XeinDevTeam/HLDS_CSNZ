#ifndef IREGISTRY_H
#define IREGISTRY_H

#ifdef _WIN32
#pragma once
#endif

class IRegistry
{
public:
	virtual void Init(void) = 0;
	virtual void Shutdown(void) = 0;
	virtual int ReadInt(const char *key, int defaultValue = 0) = 0;
	virtual void WriteInt(const char *key, int value) = 0;
	virtual const char *ReadString(const char *key, const char *defaultValue = NULL) = 0;
	virtual void WriteString(const char *key, const char *value) = 0;
};

class CRegistry {
public:
    virtual void Init();
    virtual void Shutdown();
    virtual int ReadInt(const char* key, int defaultValue);
    virtual void WriteInt(const char* key, int value);
    virtual const char* ReadString(const char* key, const char* defaultValue);
    virtual void WriteString(const char* key, const char* value);
    virtual ~CRegistry();

private:
    bool bValid;
    HKEY hKey;
};

extern CRegistry* registry;
#endif