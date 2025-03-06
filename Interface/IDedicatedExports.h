#pragma once

#include "interface.h"

class IDedicatedExports : public IBaseInterface
{
public:
    virtual ~IDedicatedExports() {};
    virtual void Sys_Printf(const char* text) = 0;
};

#define VENGINE_DEDICATEDEXPORTS_API_VERSION "VENGINE_DEDICATEDEXPORTS_API_VERSION001"
