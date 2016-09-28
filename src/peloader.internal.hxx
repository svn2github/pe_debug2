#ifndef _PELOADER_INTERNAL_
#define _PELOADER_INTERNAL_

#define NOMINMAX
#include <Windows.h>

struct IMAGE_PE_HEADER
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    // Rest is machine dependent.
};

#endif //_PELOADER_INTERNAL_