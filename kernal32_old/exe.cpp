#include "stdafx.h"
#include "exe.h"
#include "log.h"

static const DWORD PAGE_SIZE = 0x100;

static size_t RoundUp(size_t nBytes)
{
    return ((nBytes - 1) & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
}

static void *DirectedVirtualAlloc(DWORD vaBase, DWORD nBytes)
{
    MEMORY_BASIC_INFORMATION mi;
    void *result;
    size_t retval;

    log_debug("Entering DirectedVirtualAlloc");

    while (true)
    {
        retval = VirtualQuery(reinterpret_cast<void *>(vaBase), &mi, 
            sizeof(mi));

        if (retval == 0)
        {
            log_debug("    VirtualQuery failed!");
            abort();
        }
        else if (mi.State != MEM_FREE)
        {
            log_debug("    %#x: In use [%#x bytes]", mi.BaseAddress, 
                mi.RegionSize);
            vaBase = reinterpret_cast<DWORD>(mi.BaseAddress) + mi.RegionSize;
        }
        else if (mi.RegionSize < nBytes)
        {
            log_debug("    %#x: Too small [%#x bytes]", mi.BaseAddress,
                mi.RegionSize);
            vaBase = reinterpret_cast<DWORD>(mi.BaseAddress) + mi.RegionSize;
        }
        else
        {
            log_debug("    %#x: Site found [%#x bytes]", mi.BaseAddress,
                mi.RegionSize);
            result = VirtualAlloc(reinterpret_cast<void *>(vaBase), nBytes,
                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

            if (result == NULL)
            {
                log_debug("    VirtualAlloc failed!: %#x", GetLastError());
                vaBase = reinterpret_cast<DWORD>(mi.BaseAddress) 
                    + mi.RegionSize;
            }
            else
            {
                break;
            }
        }
    }

    log_debug("Leaving DirectedVirtualAlloc");

    return result;
}

CExecutable::CExecutable(HMODULE hModule)
:   m_base(reinterpret_cast<BYTE *>(hModule))
{
    IMAGE_DOS_HEADER *pDosH = FromRva<IMAGE_DOS_HEADER>(0);
    m_pHeaders = FromRva<IMAGE_NT_HEADERS>(pDosH->e_lfanew);
    m_pSections = FromRva<IMAGE_SECTION_HEADER>(pDosH->e_lfanew 
        + sizeof(IMAGE_NT_HEADERS));
}

BYTE *CExecutable::AllocateSection(const char *name, size_t nBytes)
{
    ATLASSERT(strlen(name) < 8);

    log_debug("Entering AllocateSection");

    IMAGE_SECTION_HEADER *pSec = m_pSections 
        + m_pHeaders->FileHeader.NumberOfSections++;

    ZeroMemory(pSec, sizeof(IMAGE_SECTION_HEADER));

    strcpy(reinterpret_cast<char *>(pSec->Name), name);
    pSec->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE;
    pSec->Misc.VirtualSize = RoundUp(nBytes);
    pSec->SizeOfRawData = nBytes;

    DWORD exePos = 0;
    void *pMem = NULL;

    for (size_t i = 0 ; i < GetSectionCount() ; i++)
    {
        DWORD possibleExePos 
            = m_pSections[i].PointerToRawData + m_pSections[i].SizeOfRawData;
        exePos = max(exePos, possibleExePos);
    }

    pMem = DirectedVirtualAlloc(reinterpret_cast<DWORD>(m_base), 
        RoundUp(nBytes));
    pSec->VirtualAddress = ToRva(pMem);
    pSec->PointerToRawData = RoundUp(exePos);

    FixUpSections();

    log_debug("Leaving AllocateSection");

    return reinterpret_cast<BYTE *>(pMem);
}

void CExecutable::DeleteSection(WORD n)
{
    memmove(m_pSections + n, m_pSections + n + 1, 
        sizeof(IMAGE_SECTION_HEADER) * (GetSectionCount() - n - 1));
    m_pHeaders->FileHeader.NumberOfSections--;

    FixUpSections();
}

DWORD CExecutable::GetHeaderSize(void) const
{
    return sizeof(IMAGE_NT_HEADERS)
        + FromRva<IMAGE_DOS_HEADER>(0)->e_lfanew
        + GetSectionCount() * sizeof(IMAGE_SECTION_HEADER);
}

IMAGE_NT_HEADERS *CExecutable::GetNtHeaders(void) const
{
    return m_pHeaders;
}

IMAGE_SECTION_HEADER *CExecutable::GetSection(size_t n) const
{
	ATLASSERT(n < GetSectionCount());

	return m_pSections + n;
}

WORD CExecutable::GetSectionCount(void) const
{
    return m_pHeaders->FileHeader.NumberOfSections;
}

void CExecutable::FixUpSections()
{
    DWORD size = 0;

    // SizeOfImage seems to refer to the VIRTUAL size, which is a bit of
    // a meaningless quantity...

    for (size_t i = 0 ; i < GetSectionCount() ; i++)
    {
        IMAGE_SECTION_HEADER *pSec = m_pSections + i;
        size = max(size, pSec->VirtualAddress + pSec->Misc.VirtualSize);

        if (i > 0)
        {
            IMAGE_SECTION_HEADER *pPrevSec = pSec - 1;
            pPrevSec->Misc.VirtualSize = max(pPrevSec->Misc.VirtualSize,
                pSec->VirtualAddress - pPrevSec->VirtualAddress);
        }
    }

    m_pHeaders->OptionalHeader.SizeOfImage = RoundUp(size);
}
