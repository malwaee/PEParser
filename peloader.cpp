//Parsing the headers
//Parsing the section table
//Fixing the IAT
//Fixing Relocations

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include "peloader.h"

typedef BOOL (WINAPI *Type_DllMain)(HMODULE, DWORD, LPVOID);

#pragma region peLoaderImpl



//Create a pointer value
#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))

FARPROC _GetProcAddress(HMODULE hModule, LPCSTR lpName)
{
    if(!hModule && !lpName)
     return NULL;

     PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
     if(pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
     return NULL;

     PIMAGE_NT_HEADERS  pImageNtHeaders = MakePointer(PIMAGE_NT_HEADERS, hModule, pImageDosHeader->e_lfanew);
     if(pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
     return NULL;

     if(pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
     return NULL;

     PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = MakePointer(PIMAGE_EXPORT_DIRECTORY, hModule, pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
     PDWORD pNameTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfNames);

     for(DWORD i=0; i<pImageExportDirectory->AddressOfNames; i++)
     {
        if(!_strcmpA(lpName, (char*)hModule + pNameTable[i]))
        {
            PWORD pOrdinalTable = MakePointer(PWORD, hModule, pImageExportDirectory->AddressOfNameOrdinals);
            PDWORD pAddressTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfFunctions);
            DWORD dwAddressOffset = pAddressTable[pOrdinalTable[i]];
            FARPROC proc = (FARPROC)MakePointer(PVOID, hModule, dwAddressOffset);
            return proc;
        }
     }
     return NULL;
}


HMODULE _GetModuleHandle(LPCWSTR lpModuleName)
{
    typedef struct _UNICODE_STRING 
    {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
   } UNICODE_STRING;


  typedef UNICODE_STRING *PUNICODE_STRING;
  typedef const UNICODE_STRING *PCUNICODE_STRING;

  typedef struct _LDR_DATA_TABLE_ENTRY 
  {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
  } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

  typedef struct _PEB_LDR_DATA 
  {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
  } PEB_LDR_DATA, *PPEB_LDR_DATA;

#ifdef _WIN64
  typedef struct _PEB 
  {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[21];
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    BYTE Reserved3[520];
    PVOID PostProcessInitRoutine;
    BYTE Reserved4[136];
    ULONG SessionId;
  } PEB, *PPEB;
#else
  typedef struct _PEB 
  {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    LPVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    LPVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
  } PEB, *PPEB;
#endif

//Get the base address of the peb struct
#ifdef _WIN64
  PPEB pPeb = (PPEB)__readgsqword(0x60);
#else 
  PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

  if(pPeb && pPeb->Ldr)
  {
    //Get the pointer value of PEB_LDR_DATA
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

    //And get the header of the InLoadOrderMemoryList
    PLIST_ENTRY pHeaderOfModuleList = &(pLdr->InLoadOrderModuleList);
     if (pHeaderOfModuleList->Flink != pHeaderOfModuleList) 
     {
      PLDR_DATA_TABLE_ENTRY pEntry = NULL;
      PLIST_ENTRY pCur = pHeaderOfModuleList->Flink;

      // Find Entry of the fake module
      do {
        pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
        // OK, got it
        if (0 == _stricmpW(pEntry->BaseDllName.Buffer, lpModuleName)) 
        {
          HMODULE ret = (HMODULE)pEntry->BaseAddress;
          return ret;
          break;
        }
        pEntry = NULL;
        pCur = pCur->Flink;
      } while (pCur != pHeaderOfModuleList);
    }
  }

  return NULL;

  }


PAPI_PTR_TABLE InitApiTable() 
{
  wchar_t wszKernel[] = {'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0};
  HMODULE hKernelModule = _GetModuleHandle(wszKernel);
  if (!hKernelModule)
    return NULL;

  char szGetProcAddress[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0};
  Type_GetProcAddress pfnGetProcAddress = (Type_GetProcAddress)_GetProcAddress(hKernelModule, szGetProcAddress);
  if (!pfnGetProcAddress)
    pfnGetProcAddress = (Type_GetProcAddress)_GetProcAddress;

  char szGlobalAlloc[] = {'G', 'l', 'o', 'b', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0};
  char szGlobalFree[] = {'G', 'l', 'o', 'b', 'a', 'l', 'F', 'r', 'e', 'e', 0};
  Type_GlobalAlloc pfnGlobalAlloc = (Type_GlobalAlloc)_GetProcAddress(hKernelModule, szGlobalAlloc);
  Type_GlobalFree pfnGlobalFree = (Type_GlobalFree)_GetProcAddress(hKernelModule, szGlobalFree);
  if (!pfnGlobalAlloc || !pfnGlobalFree)
    return NULL;

  PAPI_PTR_TABLE pApis = (PAPI_PTR_TABLE)pfnGlobalAlloc(GPTR, sizeof(API_PTR_TABLE));
  if (!pApis)
    return NULL;

  pApis->pfnGetProcAddress = pfnGetProcAddress;
  pApis->pfnGlobalAlloc = pfnGlobalAlloc;
  pApis->pfnGlobalFree = pfnGlobalFree;

  do {
    char szGetModuleHandleA[] = {'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0};
    pApis->pfnGetModuleHandleA = reinterpret_cast<Type_GetModuleHandle>(pfnGetProcAddress(hKernelModule, szGetModuleHandleA));
    if (!pApis->pfnGetModuleHandleA)
      break;

    char szLoadLibraryA[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    pApis->pfnLoadLibraryA = reinterpret_cast<Type_LoadLibrary>(pfnGetProcAddress(hKernelModule, szLoadLibraryA));
    if (!pApis->pfnGetModuleHandleA)
      break;

    char szVirtualAlloc[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0};
    pApis->pfnVirtualAlloc = reinterpret_cast<Type_VirtualAlloc>(pfnGetProcAddress(hKernelModule, szVirtualAlloc));
    if (!pApis->pfnGetModuleHandleA)
      break;

    char szVirtualFree[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0};
    pApis->pfnVirtualFree = reinterpret_cast<Type_VirtualFree>(pfnGetProcAddress(hKernelModule, szVirtualFree));
    if (!pApis->pfnGetModuleHandleA)
      break;

    char szVirtualProtect[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0};
    pApis->pfnVirtualProtect = reinterpret_cast<Type_VirtualProtect>(pfnGetProcAddress(hKernelModule, szVirtualProtect));
    if (!pApis->pfnGetModuleHandleA)
      break;

    return pApis;
  } while (0);

  return NULL;
}

/// <summary>
/// Verifies the format of the buffer content.
/// </summary>
/// <param name="pBuffer">The buffer containing the file data.</param>
/// <returns>True if the data is valid PE format.</returns>
BOOL IsValidPE(PE_IMAGE* pPEImage, LPVOID lpImageBase) 
{
  // Validate the parameters
  if (NULL == pPEImage || NULL == pPEImage->pApis)
    return FALSE;

  // Initialize the return value
  BOOL br = FALSE;

  // Get the DOS header
  PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lpImageBase;

  // Check the MZ signature
  if(pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
  {
    printf("Error checking the MZ signature\n");
    goto _Exit;
  }

  // Check PE signature
  PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, lpImageBase, pImageDosHeader->e_lfanew);
  if(IMAGE_NT_SIGNATURE != pImageNtHeader->Signature)
  {
    printf("Error checking  PE signature\n");
     goto _Exit;
  }

#ifdef _WIN64
  // Check the machine type
  if (IMAGE_FILE_MACHINE_AMD64 == pImageNtHeader->FileHeader.Machine) 
  {
    if(IMAGE_NT_OPTIONAL_HDR64_MAGIC != pImageNtHeader->OptionalHeader.Magic)
    {
      printf("Error checking the Machine type\n");
     goto _Exit;
    }
  }
#else
  // Check the machine type
  if (IMAGE_FILE_MACHINE_I386 == pImageNtHeader->FileHeader.Machine) 
  {
      if(IMAGE_NT_OPTIONAL_HDR32_MAGIC != pImageNtHeader->OptionalHeader.Magic)
      goto _Exit;
  }
#endif
  else
    br = TRUE;

_Exit:
  // If this is invalid PE file data return error
  if (!br)
  {
    printf("Invalid PE file data\n");
    pPEImage->dwErrorCode = ERROR_BAD_PE_FORMAT;
  }
  return br;
}

/// <summary>
/// Maps all the sections.
/// </summary>
/// <param name="pPEImage">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
BOOL MapPESections(PE_IMAGE* pPEImage, LPVOID lpImageBase) 
{
  // Validate
  if (NULL == pPEImage || NULL == pPEImage->pApis || NULL == lpImageBase)
    return FALSE;

  // Function pointer
  Type_VirtualAlloc pfnVirtualAlloc = (Type_VirtualAlloc)(pPEImage->pApis->pfnVirtualAlloc);
  Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pPEImage->pApis->pfnVirtualFree);

  // Convert to IMAGE_DOS_HEADER
  PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(lpImageBase);

  // Get the pointer to IMAGE_NT_HEADERS
  PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

  // Get the section count
  int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;

  // Get the section header
  PIMAGE_SECTION_HEADER pImageSectionHeader =
      MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

  // Find the last section limit
  DWORD dwImageSizeLimit = 0;
  for (int i = 0; i < nNumberOfSections; ++i) 
  {
    if (0 != pImageSectionHeader[i].VirtualAddress) 
    {
      if (dwImageSizeLimit < (pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
        dwImageSizeLimit = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData;
    }
  }

  // Remove. The VirtualAlloc will do this for use
  // Align the last image size limit to the page size
  // dwImageSizeLimit = dwImageSizeLimit + pPEImage->pParams->dwPageSize - 1;
  // dwImageSizeLimit &= ~(pPEImage->pParams->dwPageSize - 1);

  // Reserve virtual memory
  LPVOID lpBase = pfnVirtualAlloc((LPVOID)(pImageNtHeader->OptionalHeader.ImageBase), dwImageSizeLimit,
                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  // Failed to reserve space at ImageBase, then it's up to the system
  if (NULL == lpBase) 
  {
    // Reserver memory in arbitrary address
    lpBase = pfnVirtualAlloc(NULL, dwImageSizeLimit, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // Failed again, return
    if (NULL == lpBase) 
    {
      pPEImage->dwErrorCode = ERROR_ALLOCATED_MEMORY_FAILED;
      return FALSE;
    }
  }

  // Commit memory for PE header
  LPVOID pDest = pfnVirtualAlloc(lpBase, pImageNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
  if (!pDest) 
  {
    pPEImage->dwErrorCode = ERROR_ALLOCATED_MEMORY_FAILED;
    return FALSE;
  }

  // Copy the data of PE header to the memory allocated
  _memmove(pDest, lpImageBase, pImageNtHeader->OptionalHeader.SizeOfHeaders);

  // Store the base address of this module.
  pPEImage->lpBase = pDest;
  pPEImage->dwSizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
  pPEImage->bLoadOk = TRUE;

  // Get the DOS header, NT header and Section header from the new PE header
  // buffer
  pImageDosHeader = (PIMAGE_DOS_HEADER)pDest;
  pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
  pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

  // Map all section data into the memory
  LPVOID pSectionBase = NULL;
  LPVOID pSectionDataSource = NULL;
  for (int i = 0; i < nNumberOfSections; ++i) 
  {
    if (0 != pImageSectionHeader[i].VirtualAddress) 
    {
      // Get the section base
      pSectionBase = MakePointer(LPVOID, lpBase, pImageSectionHeader[i].VirtualAddress);

      if (0 == pImageSectionHeader[i].SizeOfRawData) 
      {
        DWORD size = 0;
        if (pImageSectionHeader[i].Misc.VirtualSize > 0) 
        {
          size = pImageSectionHeader[i].Misc.VirtualSize;
        } else 
        {
          size = pImageNtHeader->OptionalHeader.SectionAlignment;
        }

        if (size > 0) 
        {
          // If the size is zero, but the section alignment is not zero then
          // allocate memory with the alignment
          pDest = pfnVirtualAlloc(pSectionBase, size, MEM_COMMIT, PAGE_READWRITE);
          if (NULL == pDest) 
          {
            pPEImage->dwErrorCode = ERROR_ALLOCATED_MEMORY_FAILED;
            return FALSE;
          }

          // Always use position from file to support alignments smaller than
          // page size.
          _memset(pSectionBase, 0, size);
        }
      } else 
      {
        // Commit this section to target address
        pDest = pfnVirtualAlloc(pSectionBase, pImageSectionHeader[i].SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
        if (NULL == pDest) 
        {
          pPEImage->dwErrorCode = ERROR_ALLOCATED_MEMORY_FAILED;
          return FALSE;
        }

        // Get the section data source and copy the data to the section buffer
        pSectionDataSource = MakePointer(LPVOID, lpImageBase, pImageSectionHeader[i].PointerToRawData);
        _memmove(pDest, pSectionDataSource, pImageSectionHeader[i].SizeOfRawData);
      }

      // Get next section header
      pImageSectionHeader[i].Misc.PhysicalAddress = (DWORD)(ULONGLONG)pDest;
    }
  }

  return TRUE;
}

/// <summary>
/// Relocates the module.
/// </summary>
/// <param name="pPEImage">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
BOOL RelocatePE(PE_IMAGE* pPEImage) 
{
  // Validate the parameters
  if (NULL == pPEImage || NULL == pPEImage->pImageDosHeader)
    return FALSE;

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pPEImage->pImageDosHeader, pPEImage->pImageDosHeader->e_lfanew);

  // Get the delta of the real image base with the predefined
  LONGLONG lBaseDelta = ((PBYTE)pPEImage->iBase - (PBYTE)pImageNtHeader->OptionalHeader.ImageBase);

  // This module has been loaded to the ImageBase, no need to do relocation
  if (0 == lBaseDelta)
    return TRUE;

  if (0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ||
      0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    return TRUE;

  PIMAGE_BASE_RELOCATION pImageBaseRelocation =
      MakePointer(PIMAGE_BASE_RELOCATION, pPEImage->lpBase,
                  pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

  if (NULL == pImageBaseRelocation) 
  {
    pPEImage->dwErrorCode = ERROR_INVALID_RELOCATION_BASE;
    return FALSE;
  }

  while (0 != (pImageBaseRelocation->VirtualAddress + pImageBaseRelocation->SizeOfBlock)) 
  {
    PWORD pRelocationData = MakePointer(PWORD, pImageBaseRelocation, sizeof(IMAGE_BASE_RELOCATION));

    int NumberOfRelocationData = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

    for (int i = 0; i < NumberOfRelocationData; i++) {
      if (IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12))
      {
        PDWORD pAddress =
            (PDWORD)(pPEImage->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
        *pAddress += (DWORD)lBaseDelta;
      }

#ifdef _WIN64
      if (IMAGE_REL_BASED_DIR64 == (pRelocationData[i] >> 12)) 
      {
        PULONGLONG pAddress =
            (PULONGLONG)(pPEImage->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
        *pAddress += lBaseDelta;
      }
#endif
    }

    pImageBaseRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock);
  }

  return TRUE;
}

/// <summary>
/// Resolves the import table.
/// </summary>
/// <param name="pPEImage">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
BOOL ResolveImportTable(PE_IMAGE* pPEImage) 
{
  if (NULL == pPEImage || NULL == pPEImage->pApis || NULL == pPEImage->pImageDosHeader)
    return FALSE;

  Type_GetModuleHandle pfnGetModuleHandleA = (Type_GetModuleHandle)(pPEImage->pApis->pfnGetModuleHandleA);
  Type_LoadLibrary pfnLoadLibraryA = (Type_LoadLibrary)(pPEImage->pApis->pfnLoadLibraryA);
  Type_GetProcAddress pfnGetProcAddress = (Type_GetProcAddress)(pPEImage->pApis->pfnGetProcAddress);

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pPEImage->pImageDosHeader, pPEImage->pImageDosHeader->e_lfanew);

  if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
      pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
    return TRUE;

  PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor =
      MakePointer(PIMAGE_IMPORT_DESCRIPTOR, pPEImage->lpBase,
                  pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

  for (; pImageImportDescriptor->Name; pImageImportDescriptor++) 
  {
    // Get the dependent module name
    PCHAR pDllName = MakePointer(PCHAR, pPEImage->lpBase, pImageImportDescriptor->Name);

    // Get the dependent module handle
    HMODULE hMod = pfnGetModuleHandleA(pDllName);

    // Load the dependent module
    if (NULL == hMod)
      hMod = pfnLoadLibraryA(pDllName);

    // Failed
    if (NULL == hMod) 
    {
      pPEImage->dwErrorCode = ERROR_IMPORT_MODULE_FAILED;
      return FALSE;
    }
    // Original thunk
    PIMAGE_THUNK_DATA pOriginalThunk = NULL;
    if (pImageImportDescriptor->OriginalFirstThunk)
      pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pPEImage->lpBase, pImageImportDescriptor->OriginalFirstThunk);
    else
      pOriginalThunk = MakePointer(PIMAGE_THUNK_DATA, pPEImage->lpBase, pImageImportDescriptor->FirstThunk);

    // IAT thunk
    PIMAGE_THUNK_DATA pIATThunk =
        MakePointer(PIMAGE_THUNK_DATA, pPEImage->lpBase, pImageImportDescriptor->FirstThunk);

    for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++) 
    {
      FARPROC lpFunction = NULL;
      if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal)) 
      {
        lpFunction = pfnGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
      } else 
      {
        PIMAGE_IMPORT_BY_NAME pImageImportByName =
            MakePointer(PIMAGE_IMPORT_BY_NAME, pPEImage->lpBase, pOriginalThunk->u1.AddressOfData);

        lpFunction = pfnGetProcAddress(hMod, (LPCSTR) & (pImageImportByName->Name));
      }

      // Write into IAT
#ifdef _WIN64
      pIATThunk->u1.Function = (ULONGLONG)lpFunction;
#else
      pIATThunk->u1.Function = (DWORD)lpFunction;
#endif
    }
  }

  return TRUE;
}

/// <summary>
/// Sets the memory protected stats of all the sections.
/// </summary>
/// <param name="pPEImage">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
BOOL SetMemProtectionFlags(PE_IMAGE* pPEImage) 
{
  if (NULL == pPEImage || NULL == pPEImage->pApis)
    return FALSE;

  int ProtectionMatrix[2][2][2] = 
  {
      {
          // not executable
          {PAGE_NOACCESS, PAGE_WRITECOPY},
          {PAGE_READONLY, PAGE_READWRITE},
      },
      {
          // executable
          {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
          {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
      },
  };

  Type_VirtualProtect pfnVirtualProtect = (Type_VirtualProtect)(pPEImage->pApis->pfnVirtualProtect);
  Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pPEImage->pApis->pfnVirtualFree);

  PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pPEImage->lpBase);

  ULONGLONG ulBaseHigh = 0;
#ifdef _WIN64
  ulBaseHigh = (pPEImage->iBase & 0xffffffff00000000);
#endif

  PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

  int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
  PIMAGE_SECTION_HEADER pImageSectionHeader =
      MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

  for (int idxSection = 0; idxSection < nNumberOfSections; idxSection++) 
  {
    DWORD protectFlag = 0;
    DWORD oldProtect = 0;
    BOOL isExecutable = FALSE;
    BOOL isReadable = FALSE;
    BOOL isWritable = FALSE;

    BOOL isNotCache = FALSE;
    ULONGLONG dwSectionBase = (pImageSectionHeader[idxSection].Misc.PhysicalAddress | ulBaseHigh);
    DWORD dwSecionSize = pImageSectionHeader[idxSection].SizeOfRawData;
    if (0 == dwSecionSize)
      continue;

    // This section is in this page
    DWORD dwSectionCharacteristics = pImageSectionHeader[idxSection].Characteristics;

    // Discardable
    if (dwSectionCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) 
    {
      pfnVirtualFree((LPVOID)dwSectionBase, dwSecionSize, MEM_DECOMMIT);
      continue;
    }

    // Executable
    if (dwSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
      isExecutable = TRUE;

    // Readable
    if (dwSectionCharacteristics & IMAGE_SCN_MEM_READ)
      isReadable = TRUE;

    // Writable
    if (dwSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
      isWritable = TRUE;

    if (dwSectionCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
      isNotCache = TRUE;

    protectFlag = ProtectionMatrix[isExecutable][isReadable][isWritable];
    if (isNotCache)
      protectFlag |= PAGE_NOCACHE;
    if (!pfnVirtualProtect((LPVOID)dwSectionBase, dwSecionSize, protectFlag, &oldProtect)) 
    {
      pPEImage->dwErrorCode = ERROR_PROTECT_SECTION_FAILED;
      return FALSE;
    }
  }

  return TRUE;
}

/// <summary>
/// Executes the TLS callback function.
/// </summary>
/// <param name="pPEImage">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
BOOL ExecuteTLSCallback(PE_IMAGE* pPEImage) 
{
  if (NULL == pPEImage || NULL == pPEImage->pImageDosHeader)
    return FALSE;

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pPEImage->pImageDosHeader, pPEImage->pImageDosHeader->e_lfanew);

  IMAGE_DATA_DIRECTORY imageDirectoryEntryTls = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (imageDirectoryEntryTls.VirtualAddress == 0)
    return TRUE;

  PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(pPEImage->iBase + imageDirectoryEntryTls.VirtualAddress);
  PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
  if (callback) 
  {
    while (*callback) 
    {
      (*callback)((LPVOID)pPEImage->hModule, DLL_PROCESS_ATTACH, NULL);
      callback++;
    }
  }
  return TRUE;
}

/// <summary>
/// Calls the module entry.
/// </summary>
/// <param name="pPEImage">The <see cref="MemModule" /> instance.</param>
/// <param name="dwReason">The reason of the calling.</param>
/// <returns>True if successful.</returns>
BOOL CallEntryPoint(void* pMemModule_d, DWORD dwReason) 
{
  PE_IMAGE* pPEImage = (PE_IMAGE*)pMemModule_d;
  
  if (NULL == pPEImage || NULL == pPEImage->pImageDosHeader)
    return FALSE;

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pPEImage->pImageDosHeader, pPEImage->pImageDosHeader->e_lfanew);

  Type_DllMain pfnModuleEntry = NULL;

  // If there is no entry point return false
  if (0 == pImageNtHeader->OptionalHeader.AddressOfEntryPoint)
 {
    return FALSE;
  }

  pfnModuleEntry = MakePointer(Type_DllMain, pPEImage->lpBase, pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

  if (NULL == pfnModuleEntry) 
  {
    pPEImage->dwErrorCode = ERROR_INVALID_ENTRY_POINT;
    return FALSE;
  }

  return pfnModuleEntry(pPEImage->hModule, dwReason, NULL);
}

/// <summary>
/// Gets the exported function address.
/// </summary>
/// <param name="pPEImage">The <see cref="MemModule" /> instance.</param>
/// <param name="lpName">The function name.</param>
/// <returns>The address of the function or null.</returns>
FARPROC GetExportedFunction(PE_IMAGE* pPEImage, LPCSTR lpName) 
{
  if (NULL == pPEImage || NULL == pPEImage->pImageDosHeader)
    return NULL;

  PIMAGE_NT_HEADERS pImageNtHeader =
      MakePointer(PIMAGE_NT_HEADERS, pPEImage->pImageDosHeader, pPEImage->pImageDosHeader->e_lfanew);

  PIMAGE_EXPORT_DIRECTORY pImageExportDirectory =
      MakePointer(PIMAGE_EXPORT_DIRECTORY, pPEImage->lpBase,
                  pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  PDWORD pAddressOfNames = MakePointer(PDWORD, pPEImage->lpBase, pImageExportDirectory->AddressOfNames);

  PWORD pAddressOfNameOrdinals = MakePointer(PWORD, pPEImage->lpBase, pImageExportDirectory->AddressOfNameOrdinals);

  PDWORD pAddressOfFunctions = MakePointer(PDWORD, pPEImage->lpBase, pImageExportDirectory->AddressOfFunctions);

  int nNumberOfFunctions = pImageExportDirectory->NumberOfFunctions;
  for (int i = 0; i < nNumberOfFunctions; ++i) 
  {
    DWORD dwAddressOfName = pAddressOfNames[i];

    LPCSTR pFunctionName = MakePointer(LPCSTR, pPEImage->lpBase, dwAddressOfName);

    if (0 == _strcmpA(lpName, pFunctionName)) 
    {
      WORD wOrdinal = pAddressOfNameOrdinals[i];
      DWORD dwFunctionOffset = pAddressOfFunctions[wOrdinal];
      FARPROC pfnTargetProc = MakePointer(FARPROC, pPEImage->lpBase, dwFunctionOffset);

      return pfnTargetProc;
    }
  }

  return NULL;
}

/// <summary>
/// Unmaps all the sections.
/// </summary>
/// <param name="pPEImage">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
VOID UnmapPEImage(PE_IMAGE* pPEImage) 
{
  if (NULL == pPEImage || NULL == pPEImage->pApis || FALSE == pPEImage->bLoadOk || NULL == pPEImage->lpBase)
    return;

  Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pPEImage->pApis->pfnVirtualFree);

  pfnVirtualFree(pPEImage->lpBase, 0, MEM_RELEASE);

  pPEImage->lpBase = NULL;
  pPEImage->dwCrc = 0;
  pPEImage->dwSizeOfImage = 0;
  pPEImage->bLoadOk = FALSE;
}

/// <summary>
/// Gets the CRC32 of the data.
/// </summary>
/// <param name="uInit">Number used to initialize.</param>
/// <param name="pBuf">The Buffer.</param>
/// <param name="nBufSize">The size of the buffer.</param>
UINT32 GetCRC32(UINT32 uInit, void *pBuf, UINT32 nBufSize) 
{
#define CRC32_POLY 0x04C10DB7L
  UINT32 crc = 0;
  UINT32 Crc32table[256];
  for (int i = 0; i < 256; i++) 
  {
    crc = (UINT32)(i << 24);
    for (int j = 0; j < 8; j++) 
    {
      if (crc >> 31)
        crc = (crc << 1) ^ CRC32_POLY;
      else
        crc = crc << 1;
    }
    Crc32table[i] = crc;
  }

  crc = uInit;
  UINT32 nCount = nBufSize;
  PUCHAR p = (PUCHAR)pBuf;
  while (nCount--) 
  {
    crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];
  }

  return crc;
}


BOOL LoadPEImage(PE_IMAGE* pPEImage, LPVOID lpImageBase, BOOL bCallEntry)
{
    if(NULL == pPEImage || NULL == lpImageBase || NULL == pPEImage->pApis)
    return false;

    pPEImage->dwErrorCode = ERROR_SUCCESS;

    //Verify file format
    if(FALSE == IsValidPE(pPEImage, lpImageBase))
     return false;

    //Map pe header and section table to memory
    if(FALSE == MapPESections(pPEImage, lpImageBase))
    return false;

    //Relocate the module base
    if(FALSE == RelocatePE(pPEImage))
    {
        UnmapPEImage(pPEImage);
        return false;
    }

    //Resolve the import table
    if(FALSE == ResolveImportTable(pPEImage))
    {
        UnmapPEImage(pPEImage);
        return false;
    }

    pPEImage->dwCrc = GetCRC32(0, pPEImage->lpBase, pPEImage->dwSizeOfImage);

    //correct the protect flag for all section pages
    if(FALSE == SetMemProtectionFlags(pPEImage))
    {
        UnmapPEImage(pPEImage);
        return FALSE;
    }

    if(FALSE == ExecuteTLSCallback(pPEImage))
    return FALSE;

    if(bCallEntry)
    {
        if(FALSE == CallEntryPoint((void*)pPEImage, DLL_PROCESS_ATTACH))
        {
            UnmapPEImage(pPEImage);
            return FALSE;
        }
    }

  return TRUE;
}


VOID** LoadPEImageEx(LPVOID lpImageBase, BOOL bCallEntry, DWORD* pdwError)
{
    printf("LoadPEImageEx called, Initializing API functions\n");
    PAPI_PTR_TABLE pAPIs = InitApiTable();
    if(!pAPIs)
    {
        if(pdwError)
            *pdwError = ERROR_INVALID_WIN32_ENV;
            return NULL;
    }

    printf("Initializing APIs successful\n");

    Type_GlobalAlloc pfnGlobalAlloc = pAPIs->pfnGlobalAlloc;
    PE_IMAGE*  pPEImage = (PE_IMAGE*)pfnGlobalAlloc(GPTR, sizeof(PE_IMAGE));
    if(!pPEImage)
    {
        if(pdwError)
        *pdwError = ERROR_INVALID_WIN32_ENV;
        return NULL;
    }


    pPEImage->pApis = pAPIs;
    pPEImage->bCallEntry = bCallEntry;
    pPEImage->bLoadOk = FALSE;
    pPEImage->dwErrorCode = ERROR_OK;

    printf("Calling LoadPEImage\n");
    if(LoadPEImage(pPEImage, lpImageBase, bCallEntry))
    {
        if(pdwError)
        *pdwError = 0;
        return (VOID**)pPEImage;
    }

    if(pdwError)
    {
        *pdwError = pPEImage->dwErrorCode;
        Type_GlobalFree pfnGlobalFree = pAPIs->pfnGlobalFree;
        pfnGlobalFree(pPEImage);
        pfnGlobalFree(pAPIs);
        return NULL;
    }
}



VOID FreePEImage(PE_IMAGE* pPEImage)
{
    if(pPEImage != NULL)
    {
    pPEImage->dwErrorCode = ERROR_SUCCESS;

    if(pPEImage->bCallEntry)
    CallEntryPoint((void*)pPEImage, DLL_PROCESS_DETACH);

    UnmapPEImage(pPEImage);
    }
}


VOID FreePEImageEx(VOID** pMemImage)
{
    PE_IMAGE* pPEImage = (PE_IMAGE*)pMemImage;
    FreePEImage(pPEImage);
    if(pPEImage)
    {
        Type_GlobalFree pfnGlobalFree = pPEImage->pApis->pfnGlobalFree;
        if(pfnGlobalFree)
        {
            pfnGlobalFree(pPEImage->pApis);
            pfnGlobalFree(pPEImage);
        }
    }
}



FARPROC GetDLLExport(PE_IMAGE* pPEImage, LPCSTR lpName)
{
    if(!pPEImage && !lpName)
    {
        //Get the address of the specific function
        pPEImage->dwErrorCode = ERROR_SUCCESS;
        return GetExportedFunction(pPEImage, lpName);
    }

    return NULL;
}


FARPROC GetDLLExportEx(VOID** MemModule, LPCSTR lpName)
{
    return GetDLLExport((PE_IMAGE*)MemModule, lpName);
}


LPVOID PEImageHelper(PEHELPER_METHOD method, LPVOID arg1, LPVOID arg2, LPVOID arg3)
{
    switch(method)
    {
        case PE_BOOL_LOAD:
        {
            return (LPVOID)(INT_PTR)LoadPEImageEx(arg1, (BOOL)(arg2 != 0), (DWORD*)arg3);
        }
        break;

        case PE_VOID_FREE:
        {
            FreePEImageEx((VOID**)arg1);
        }
        break;

        case PE_FARPROC_GETPROC:
        {
            return (LPVOID)GetDLLExportEx((VOID**)arg1, (LPCSTR)arg2);
        }
        break;

        default:
        break;
    }

    return 0;
}

/// <summary>
/// Gets the length of the ANSI string.
/// </summary>
/// <param name="psz">The string.</param>
int _strlenA(const char *psz) 
{
  int i = 0;
  for (; *psz; psz++, i++)
    ;
  return i;
}

/// <summary>
/// Compares the two strings.
/// </summary>
/// <param name="psza">The first string.</param>
/// <param name="pszb">The second string.</param>
int _strcmpA(const char *psza, const char *pszb) 
{
  unsigned char c1 = 0;
  unsigned char c2 = 0;

  do {
    c1 = (unsigned char)*psza++;
    c2 = (unsigned char)*pszb++;
    if (c1 == 0)
      return c1 - c2;
  } while (c1 == c2);

  return c1 - c2;
}

/// <summary>
/// Compares the two strings.
/// </summary>
/// <param name="psza">The first string.</param>
/// <param name="pszb">The second string.</param>
int _stricmpW(const wchar_t *pwsza, const wchar_t *pwszb) 
{
  unsigned short c1 = 0;
  unsigned short c2 = 0;

  do {
    c1 = (unsigned short)*pwsza++;
    if (c1 >= 65 && c1 <= 90) 
    {
      c1 = c1 + 32;
    }

    c2 = (unsigned short)*pwszb++;
    if (c2 > 65 && c2 < 90) 
    {
      c2 = c2 + 32;
    }

    if (c1 == 0)
      return c1 - c2;
  } while (c1 == c2);

  return c1 - c2;
}

/// <summary>
/// Copys the string from source to destination buffer.
/// </summary>
/// <param name="pszDest">The destination string buffer.</param>
/// <param name="pszSrc">The source string.</param>
/// <param name="nMax">Maximum count of the character to copy.</param>
wchar_t * _strcpyW(wchar_t *pszDest, const wchar_t *pszSrc, unsigned int nMax) 
{
  while (nMax--) 
  {
    *pszDest++ = *pszSrc++;
    if (*pszSrc == 0)
      break;
  }
  return pszDest;
}

#pragma optimize("gtpy", off)
/// <summary>
/// Sets the memory with specific value.
/// </summary>
void * _memset(void *pv, int c, unsigned int cb) 
{
  for (unsigned int i = 0; i < cb; i++)
    ((unsigned char *)pv)[i] = (unsigned char)c;
  return pv;
}
#pragma optimize("gtpy", on)

/// <summary>
/// Moves the source memory data to the destination buffer.
/// </summary>
/// <param name="pvDest">The destination buffer.</param>
/// <param name="pvSrc">The source memory buffer.</param>
/// <param name="cb">The count of the bytes to move.</param>
void * _memmove(void *pvDest, const void *pvSrc, unsigned int cb) 
{
  unsigned char *pb1 = 0;
  unsigned char *pb2 = 0;

  if (pvSrc < pvDest) 
  {
    pb1 = (unsigned char *)pvDest + cb - 1;
    pb2 = (unsigned char *)pvSrc + cb - 1;
    for (; cb; cb--)
      *pb1-- = *pb2--;
  } else if (pvSrc > pvDest) 
  {
    pb1 = (unsigned char *)pvDest;
    pb2 = (unsigned char *)pvSrc;
    for (; cb; cb--)
      *pb1++ = *pb2++;
  }
  return pvDest;
}

/// <summary>
/// Mark.
/// </summary>
void peLoaderCodeEnd() 
{
  return;
}

#pragma endregion peLoaderImpl


void TO_LOWERCASE(WCHAR out, WCHAR c1)  
{ 
  out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1; 
  return; 
}


LPVOID get_module_by_name(const WCHAR* module_name)
{
    PEB *peb;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PEB_LDR_DATA *ldr = peb->Ldr;

    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    for(LIST_ENTRY *current = head->Flink; current != head; current = current->Flink)
    {
        LDR_DATA_TABLE_ENTRY1* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY1, InMemoryOrderLinks);
        if (!entry || !entry->DllBase) break;

        WCHAR* curr_name = entry->BaseDllName.Buffer;
        if (!curr_name) continue;

        size_t i;
        for (i = 0; i < entry->BaseDllName.Length; i++) {
            // if any of the strings finished:
            if (module_name[i] == 0 || curr_name[i] == 0) 
            {
                break;
            }
            WCHAR c1 = 0, c2 = 0;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        // both of the strings finished, and so far they were identical:
        if (module_name[i] == 0 && curr_name[i] == 0) 
        {
            return entry->DllBase;
        }
    }

    return nullptr;
}

LPVOID get_func_by_name(LPVOID module, const char* func_name)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) 
    {
        return nullptr;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (!exportsDir->VirtualAddress) 
    {
        return nullptr;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) 
    {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) 
        {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) 
        {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return nullptr;
}


void* load_PE(char* PE_data)
{
    /** parse header */

    IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*)PE_data;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);

    DWORD hdr_image_base = p_NT_HDR->OptionalHeader.ImageBase;
    DWORD size_of_image = p_NT_HDR->OptionalHeader.SizeOfImage;
    DWORD entry_point_RVA = p_NT_HDR->OptionalHeader.AddressOfEntryPoint;
    DWORD size_of_headers = p_NT_HDR->OptionalHeader.SizeOfHeaders;
    void* function_handle = NULL;

  
typedef decltype(&LoadLibraryA) Type_LoadLibraryA;
typedef decltype(&GetProcAddress) Type_GetProcAddress;
typedef decltype(&VirtualAlloc) Type_VirtualAlloc;
typedef decltype(&VirtualProtect) Type_VirtualProtect;

printf("1\n");
wchar_t kernel32_dll_name[] = {'k','e','r','n','e','l','3','2','.','d','l','l', 0};
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);

printf("2\n");
char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A', 0};
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
  
printf("3\n");
char proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0};
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)proc_name);

printf("4\n");
char VirtualAlloc_name[] = { 'V','i','r','t','u','a','l','A','l','l','o','c', 0};
    LPVOID get_VirtualAlloc = get_func_by_name((HMODULE)base, (LPSTR)VirtualAlloc_name); 
printf("5\n");
char VirtualProtect_name[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0};
    LPVOID get_VirtualProtect = get_func_by_name((HMODULE)base, (LPSTR)VirtualProtect_name);
 
auto _LoadLibraryA =  reinterpret_cast<Type_LoadLibraryA>(load_lib);
auto _GetProcAddress = reinterpret_cast<Type_GetProcAddress>(get_proc);
auto _VirtualAlloc = reinterpret_cast<Type_VirtualAlloc>(get_VirtualAlloc);
auto _VirtualProtect = reinterpret_cast<Type_VirtualProtect>(get_VirtualProtect);


    printf("Allocating memory for PE\n");
    //Allocate memory
    char* ImageBase = (char*) VirtualAlloc(NULL, size_of_image, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(ImageBase == NULL)
    {
        //Allocation failed
        printf("VirtualAlloc failed\n");
        return (LPVOID)-1;
    }

    printf("Mapping PE sections\n");
    //Map PE sections in memory
    memcpy(ImageBase, PE_data, size_of_headers);

    //Section headers starts right after the IMAGE_NT_HEADERS struct so we do some pointer arithmetic-fu here
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1);

    //For each sections
    for(int i=0; i<p_NT_HDR->FileHeader.NumberOfSections; ++i)
    {
        //calculate the VA we need to copy the content, from the RVA 
        //section[i].VirtualAddress is a RVA, mind it
        char* dest = ImageBase + sections[i].VirtualAddress;

        //check if there is raw data to copy
        if(sections[i].SizeOfRawData > 0)
        {
            //We copy SizeOfRaw data bytes, from the offset PointerToRawData in the file
            memcpy(dest, PE_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }
        else
        {
            memset(dest, 0, sections[i].Misc.VirtualSize);
        }
    }

    printf("Handle PE imports\n");
    //Handle PE imports
    IMAGE_DATA_DIRECTORY* data_directory = p_NT_HDR->OptionalHeader.DataDirectory;

    //Load the address of the import descriptors array
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*) (ImageBase + data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    printf("loop of the import descriptors\n");
    //This array is null terminated
    for(int i=0; import_descriptors[i].OriginalFirstThunk != 0; ++i)
    {
        printf("Getting the name of the dll to import\n");
        //Get the name of the dll and import it
        char* module_name = ImageBase + import_descriptors[i].Name;
        HMODULE import_module = LoadLibraryA(module_name);
        if(import_module == NULL)
        {
           printf("NULL import module\n");
            return NULL;
        }
         printf("Lookup Table\n");
        //The lookup table points to the function names or ordinals => it is the IDT
        IMAGE_THUNK_DATA* lookup_table = (IMAGE_THUNK_DATA*) (ImageBase + import_descriptors[i].OriginalFirstThunk);

        //The address table is a copy of the lookup table at first
        //but we put the addresses of the loaded function inside => it is the IAT
        IMAGE_THUNK_DATA* address_table = (IMAGE_THUNK_DATA*) (ImageBase + import_descriptors[i].FirstThunk);
        
        printf("loop of the Lookup table array of AddressOfData\n");
        //Null terminated array again
        for(int i=0; lookup_table[i].u1.AddressOfData !=0; ++i)
        {

            printf("Checking the lookup tablefor the address of the function\n");
            //Check the lookup table for the addresses of the function name to import 
            DWORD lookup_addr = lookup_table[i].u1.AddressOfData;

            if((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) //If first bit is not 1
            {
                printf("Import by name\n");
                //Import by name : get the IMAGE_IMPORT_BY_NAME struct
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*) ImageBase + lookup_addr;
                //This struct points to the ascii function
                char* func_name = (char*) &(image_import->Name);
                //Get that function address from its module and name
                printf("Getting the function address\n");
                function_handle = (void*)GetProcAddress(import_module, func_name);
                if(!function_handle)
                  printf("Couldn't get function address\n");
                else
                  printf("Got function address from module %s\n", func_name);
            }
                else
                {
                    printf("Import by ordinal\n");
                    //Import by ordinal, directly
                    function_handle = (void*)GetProcAddress(import_module, (LPSTR)lookup_addr);
                }
            }

            if(function_handle == NULL )
            {
                return NULL;
            }

        //Change the IAT, and put the function  address inside
        address_table[i].u1.Function = (DWORD) function_handle;
        }
    //Handle Relocations

    printf("Handle Relocations\n");
    //This is how much we shifted the ImageBase
    DWORD delta_VA_reloc = ((DWORD) ImageBase) - p_NT_HDR->OptionalHeader.ImageBase;

    //If there is a relocation table, and we actually shifted the ImageBase
    if(data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0 && delta_VA_reloc !=0)
    {

        //Calculate the relocation table address
        IMAGE_BASE_RELOCATION* p_reloc = (IMAGE_BASE_RELOCATION*) (ImageBase + data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        //Once again a null terminated array
        while(p_reloc->VirtualAddress != 0)
        {

            //How many relocations in this block
            //ie the total size, minus the size of the header, divided by 2 (those are words so 2 bytes for each)
            DWORD size = (p_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            //The first relocation element in the block , right after the header (using pointer arithmetic again)
            WORD* reloc = (WORD*) (p_reloc + 1);
            for(int i=0; i<size; ++i)
            {
                //Type is the first 4 bits of the relocation word
                int type = reloc[i] >> 12;
                int offset = reloc[i] & 0x0fff;
                //This is the address we are going to change
                DWORD* change_addr = (DWORD*) (ImageBase + p_reloc->VirtualAddress + offset);

                //There is only one type used that needs to make a change
                switch(type)
                {
                    case IMAGE_REL_BASED_HIGHLOW:
                    *change_addr += delta_VA_reloc;
                    break;
                    default:
                    break;
                }
            } 

            //Switch to the next relocation based on the size
            p_reloc = (IMAGE_BASE_RELOCATION*) (((DWORD)p_reloc) + p_reloc->SizeOfBlock);
        }
    }

    //Map PE sections privileges

    //Set permissions for the PE header to read only
    DWORD oldProtect;
    VirtualProtect(ImageBase, p_NT_HDR->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

    for(int i=0; i<p_NT_HDR->FileHeader.NumberOfSections; ++i)
    {
        char* dest = ImageBase + sections[i].VirtualAddress;
        DWORD s_perm = sections[i].Characteristics;
        DWORD v_perm = 0;  //Flags are not the same between virtualprotect and section header
        if(s_perm & IMAGE_SCN_MEM_EXECUTE)
        {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        else
        {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }
        VirtualProtect(dest, sections[i].Misc.VirtualSize, v_perm, &oldProtect);
    }
    return (void*) (ImageBase + entry_point_RVA);
}