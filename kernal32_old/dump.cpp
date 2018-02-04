#include "stdafx.h"
#include "dump.h"
#include "exe.h"
#include "imports.h"
#include "log.h"

struct IATINFO
{
	DWORD *pPtrs;
	ATL::CString dllName;
	ATL::CAtlArray<const IMPORT *> entries;
};

typedef ATL::CAutoPtr<IATINFO> PIATINFO;
typedef ATL::CAtlArray<PIATINFO, ATL::CAutoPtrElementTraits<IATINFO> > 
	INFOARRAY;
typedef ATL::CAutoPtr<INFOARRAY> PINFOARRAY;

// Confirm that this is actually an IAT
static bool CheckIAT(const CImportCache *pImports, HMODULE hModule, 
	const DWORD *pPtr)
{
	for ( ; *pPtr != NULL ; pPtr++)
	{
		const IMPORT *pImp = pImports->LookupImport(*pPtr);

		if (pImp == NULL || pImp->hModule != hModule)
		{
			return false;
		}
	}

	return true;
}

static PIATINFO AnalyzeIAT(CExecutable *pEXE, const CImportCache *pImports, 
    HMODULE hModule, DWORD **ppPtr)
{
	PIATINFO pIat( new IATINFO() );

    log_debug("Analyzing IAT for %s", pImports->LookupDLL(hModule));

	pIat->pPtrs = *ppPtr;
	pIat->dllName = pImports->LookupDLL(hModule);

	for ( ; **ppPtr != NULL ; (*ppPtr)++)
	{
		const IMPORT *pImp = pImports->LookupImport(**ppPtr);
		pIat->entries.Add(pImp);

        if (pImp->name.IsEmpty())
        {
            log_debug("    %p -> #%d", *ppPtr, pImp->ordinal);
        }
        else
        {
            log_debug("    %p -> %s", *ppPtr, pImp->name);
        }
	}

	return pIat;
}

static PINFOARRAY FindIATs(CExecutable *pExe, const CImportCache *pImports)
{
	PINFOARRAY pResult( new INFOARRAY() );

	for (size_t i = 0 ; i < pExe->GetSectionCount() ; i++)
	{
		const IMAGE_SECTION_HEADER *pSec = pExe->GetSection(i);
        DWORD *pPtrs = pExe->FromRva<DWORD>(pSec->VirtualAddress);
        DWORD *pEnd = pPtrs + pSec->Misc.VirtualSize / 4;

		for ( ; pPtrs < pEnd ; pPtrs++)
		{
			// Basic range check to filter out most non-pointers
			if (*pPtrs > 0x100000 && *pPtrs < 0xC0000000)
			{
				const IMPORT *pImp = pImports->LookupImport(*pPtrs);

				if (pImp != NULL && CheckIAT(pImports, pImp->hModule, pPtrs))
				{
					PIATINFO pIat = AnalyzeIAT(pExe, pImports, pImp->hModule, 
						&pPtrs);
					pResult->Add(pIat);
				}
			}
		}
	}

	return pResult;
}

static void AllocImportDescriptors(CExecutable *pExe, const INFOARRAY *pInfos,
    IMAGE_IMPORT_DESCRIPTOR **ppDescs, char **ppText)
{
    // imp desc list is terminated by a null entry, we count it here.
    DWORD nBytes = sizeof(IMAGE_IMPORT_DESCRIPTOR);

    for (size_t i = 0 ; i < pInfos->GetCount() ; i++)
    {
        const IATINFO *pIat = pInfos->GetAt(i);

        // Count descriptor, DLL name, and string NUL terminator
        nBytes += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        nBytes += pIat->dllName.GetLength() + 1;

        for (size_t j = 0 ; j < pIat->entries.GetCount() ; j++)
        {
            const IMPORT *pEntry = pIat->entries.GetAt(j);

            if (!pEntry->name.IsEmpty())
            {
                nBytes += pEntry->name.GetLength() + 3;
            }
        }
    }

    log_debug("Allocating %#x byte .idata section", nBytes);

    BYTE *pSection = pExe->AllocateSection(".idata", nBytes);
    *ppDescs = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(pSection);
    *ppText = reinterpret_cast<char *>(pSection 
        + (pInfos->GetCount() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    IMAGE_NT_HEADERS *pNtH = pExe->GetNtHeaders();
    IMAGE_DATA_DIRECTORY *pImportDir =  
        &pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pImportDir->Size = nBytes;
    pImportDir->VirtualAddress = pExe->ToRva(*ppDescs);
}

static void EmitImportDescriptors(CExecutable *pExe, const INFOARRAY *pInfos)
{
    IMAGE_IMPORT_DESCRIPTOR *pDesc;
    char *pText;

    AllocImportDescriptors(pExe, pInfos, &pDesc, &pText);

    for (size_t i = 0 ; i < pInfos->GetCount() ; i++, pDesc++)
    {
        IATINFO *pIat = pInfos->GetAt(i);
        DWORD *pRva = pIat->pPtrs;

        log_debug("Emitting import descriptors and import records for %s",
            pIat->dllName);

        pDesc->Name = pExe->ToRva(pText);
        pDesc->FirstThunk = pExe->ToRva(pIat->pPtrs);

        strcpy(pText, pIat->dllName);
        pText += pIat->dllName.GetLength() + 1;

        for (size_t j = 0 ; j < pIat->entries.GetCount() ; j++, pRva++)
        {
            const IMPORT *pEntry = pIat->entries.GetAt(j);

            if (pEntry->name.IsEmpty())
            {
                // Import by ordinal
                *pRva = 0x80000000 | pEntry->ordinal;
            }
            else
            {
                // Convert back to an IMPORT_BY_NAME RVA
                *pRva = pExe->ToRva(pText);

                pText += 2;
                strcpy(pText, pEntry->name);
                pText += pEntry->name.GetLength() + 1;
            }
        }
    }
}

static void WriteOutExe(const CExecutable *pExe, const char *filename)
{
    ATL::CHandle hFile;
    OVERLAPPED ovl;
    DWORD out;

    log_debug("Opening %s", filename);

    ZeroMemory(&ovl, sizeof(ovl));
    hFile.Attach( CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        0, NULL) );

    log_debug("Writing out EXE");

    // Emit header
    WriteFile(hFile, pExe->FromRva<BYTE>(0), pExe->GetHeaderSize(), &out,NULL);

    // Emit sections
    for (size_t i = 0 ; i < pExe->GetSectionCount() ; i++)
    {
        const IMAGE_SECTION_HEADER *pSec = pExe->GetSection(i);

        ovl.Offset = pSec->PointerToRawData;
        WriteFile(hFile, pExe->FromRva<BYTE>(pSec->VirtualAddress), 
            pSec->SizeOfRawData , &out, &ovl);
    }
}

void DumpExe(CExecutable *pExe, const CImportCache *pImports, 
    const char *filename)
{
	PINFOARRAY pInfos = FindIATs(pExe, pImports);
	EmitImportDescriptors(pExe, pInfos);
	WriteOutExe(pExe, filename);
}
