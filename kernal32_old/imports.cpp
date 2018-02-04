#include "stdafx.h"
#include "imports.h"
#include "log.h"

IMPORT *CImportCache::GetImportByAddr(void *addr)
{
	DWORD dwAddr = reinterpret_cast<DWORD>(addr);
    IMPORT *pImp = m_importsByAddr[dwAddr];

    if (pImp == NULL)
    {
        pImp = new IMPORT();
        m_importsByAddr.SetAt(dwAddr, ATL::CAutoPtr<IMPORT>(pImp) );
    }

    return pImp;
}

ATL::CString CImportCache::LookupDLL(HMODULE hModule) const
{
	ATL::CString name;

    m_moduleToName.Lookup(hModule, name);

	return name;
}

const IMPORT *CImportCache::LookupImport(DWORD addr) const
{
	IMPORT *pImp = NULL;

    m_importsByAddr.Lookup(addr, pImp);

	return pImp;
}

void CImportCache::TouchDLL(HMODULE hModule, const char *name)
{
    m_moduleToName[hModule] = ATL::CString(name);
}

void CImportCache::TouchImportName(HMODULE hModule, void *addr, 
    const char *name)
{
    IMPORT *pImp = GetImportByAddr(addr);

    log_debug("Touched %s!%s", LookupDLL(hModule), name);

    pImp->hModule = hModule;
    pImp->name = name;
}

void CImportCache::TouchImportOrdinal(HMODULE hModule, void *addr, 
    WORD ordinal)
{
    IMPORT *pImp = GetImportByAddr(addr);

    log_debug("Touched %s!#%d", LookupDLL(hModule), ordinal);

    pImp->hModule = hModule;
    pImp->ordinal = ordinal;
}
