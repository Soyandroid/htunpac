#pragma once

#include <atlbase.h>
#include <atlcoll.h>
#include <atlstr.h>

struct IMPORT
{
    IMPORT()
    :   hModule(NULL),
        ordinal(0)
    {}

    HMODULE hModule;
    ATL::CString name;
    WORD ordinal;
};

class CImportCache
{
public:
    ATL::CString LookupDLL(HMODULE hModule) const;
    const IMPORT *LookupImport(DWORD addr) const;
    void TouchDLL(HMODULE hModule, const char *dll);
    void TouchImportName(HMODULE hModule, void *addr, const char *name);
    void TouchImportOrdinal(HMODULE hModule, void *addr, WORD ordinal);

private:
    IMPORT *GetImportByAddr(void *addr);

    ATL::CAtlMap<HMODULE, ATL::CString> m_moduleToName;
    ATL::CAtlMap<
        DWORD, 
        ATL::CAutoPtr<IMPORT>,
        ATL::CElementTraits<DWORD>,
        ATL::CAutoPtrElementTraits<IMPORT> > m_importsByAddr;
};
