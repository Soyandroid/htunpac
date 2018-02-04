#include "stdafx.h"
#include "util.h"

#include <stdio.h>
#include <windows.h>

void Trace(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;

    va_start(ap, fmt);
    vsprintf(buf, fmt, ap);
    va_end(ap);

    OutputDebugString(buf);
}
