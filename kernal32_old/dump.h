#pragma once

class CExecutable;
class CImportCache;

void DumpExe(CExecutable *pExe, const CImportCache *pImports, 
    const char *filename);
