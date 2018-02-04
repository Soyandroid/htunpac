#pragma once

#include <windows.h>
#include <stdint.h>

class CExecutable
{
public:
    CExecutable(HMODULE hModule);

    BYTE *AllocateSection(const char *name, uint32_t nBytes);
    void DeleteSection(WORD n);
	IMAGE_SECTION_HEADER *GetSection(uint32_t n) const;
    DWORD GetHeaderSize(void) const;
    IMAGE_NT_HEADERS *GetNtHeaders(void) const;
    WORD GetSectionCount(void) const;

    template<typename T> 
    T *FromRva(DWORD rva) const
    {
        return reinterpret_cast<T *>(m_base + rva);
    }

    template<typename T>
    DWORD ToRva(const T *pX) const
    {
        return reinterpret_cast<const BYTE *>(pX) - m_base;
    }

    DWORD ToRva(DWORD x) const
    {
        return reinterpret_cast<const BYTE *>(x) - m_base;
    }

private:
    void FixUpSections();

    BYTE *m_base;
    IMAGE_NT_HEADERS *m_pHeaders;
    IMAGE_SECTION_HEADER *m_pSections;
};