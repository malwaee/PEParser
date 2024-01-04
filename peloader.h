#ifndef _PELOADER_H_INCLUDED
#define _PELOADER_H_INCLUDED
#pragma once
#include <windows.h>
#include <winternl.h>

#ifdef __cplusplus
extern "C" 
{
#endif

#define ERROR_OK 0
#define ERROR_BAD_PE_FORMAT 1
#define ERROR_ALLOCATED_MEMORY_FAILED 2
#define ERROR_INVALID_RELOCATION_BASE 3
#define ERROR_IMPORT_MODULE_FAILED 4
#define ERROR_PROTECT_SECTION_FAILED 5
#define ERROR_INVALID_ENTRY_POINT 6
#define ERROR_INVALID_WIN32_ENV 0xff


typedef decltype(&GetProcAddress) Type_GetProcAddress;
typedef decltype(&GetModuleHandleA) Type_GetModuleHandle;
typedef decltype(&LoadLibraryA) Type_LoadLibrary;
typedef decltype(&VirtualAlloc) Type_VirtualAlloc;
typedef decltype(&VirtualFree) Type_VirtualFree;
typedef decltype(&VirtualProtect) Type_VirtualProtect;
typedef decltype(&GlobalAlloc) Type_GlobalAlloc;
typedef decltype(&GlobalFree) Type_GlobalFree;




//Function table
typedef struct _API_PTR_TABLE
{
    Type_GetProcAddress pfnGetProcAddress;  
    Type_GetModuleHandle pfnGetModuleHandleA;
    Type_LoadLibrary pfnLoadLibraryA;
    Type_VirtualAlloc pfnVirtualAlloc;
    Type_VirtualFree pfnVirtualFree;
    Type_VirtualProtect pfnVirtualProtect;
    Type_GlobalAlloc pfnGlobalAlloc;
    Type_GlobalFree pfnGlobalFree;
}API_PTR_TABLE, *PAPI_PTR_TABLE;

//Represents the PE Image instance
typedef struct _PE_IMAGE
{
union
  {
#if _WIN64
    ULONGLONG iBase;
#else
    DWORD iBase;
#endif
    HMODULE hModule;
    LPVOID lpBase;
    PIMAGE_DOS_HEADER pImageDosHeader; //PE image Base
  };

  DWORD dwSizeOfImage; //PE image Size
  DWORD dwCrc; //PE image CRC

  PAPI_PTR_TABLE pApis; //Pointer to parameters
  BOOL bCallEntry; //Call Module entry
  BOOL bLoadOk;  //PE image is loaded ok?
  DWORD dwErrorCode; //Last Error code
}PE_IMAGE;


// enhanced version of LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY1 
{
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY1, * PLDR_DATA_TABLE_ENTRY1;


typedef enum _PE_HELPER_METHOD
{ PE_BOOL_LOAD, PE_VOID_FREE, PE_FARPROC_GETPROC,}PEHELPER_METHOD;

typedef LPVOID(__stdcall *Type_MemModuleHelper)(PEHELPER_METHOD, LPVOID, LPVOID, LPVOID);
LPVOID  PEImageHelper(PEHELPER_METHOD method, LPVOID arg1, LPVOID arg2, LPVOID arg3);
void** LoadPEImageEx(LPVOID lpImageBase, BOOL bCallEntry, DWORD *pdwError);
FARPROC GetDLLExportEX(void** MemModuleHandle, LPCSTR lpName);
VOID  FreePEImageEx(void** pMemImage);
BOOL LoadPEImage(PE_IMAGE* pPEImage, LPVOID lpImageBase, BOOL bCallEntry);
FARPROC GetDLLExport(PE_IMAGE* pPEImage, LPCSTR lpName);
FARPROC GetDLLExportEx(VOID** MemModule, LPCSTR lpName);
VOID  FreePEImage(PE_IMAGE* pPEImage);
FARPROC _GetProcAddress(HMODULE hModule, LPCSTR lpName);
HMODULE _GetModuleHandle(LPCWSTR lpName);
PAPI_PTR_TABLE InitApiTable();
BOOL IsValidPE(PE_IMAGE* pPEImage, LPVOID lpImageBase);
BOOL MapPESections(PE_IMAGE* pPEImage, LPVOID lpMemModuleBuffer);
BOOL RelocatePE(PE_IMAGE* pPEImage);
BOOL ResolveImportTable(PE_IMAGE* pPEImage);
BOOL SetMemProtectionFlags(PE_IMAGE* pPEImage);
BOOL ExecuteTLSCallback(PE_IMAGE* pPEImage);
BOOL CallEntryPoint(PE_IMAGE* pPEImage, DWORD dwReason);
FARPROC GetExportedFunction(PE_IMAGE* pPEImage, LPCSTR lpFileName);
VOID  UnmapPEImage(PE_IMAGE* pPEImage);
UINT32 GetCRC32(UINT32 uInit, void* pBuf, UINT32 nBufSize);
void* load_PE(char* PE_data);

//Memory Functions
int _strlenA(const char* psz);
int _strcmpA(const char* psza, const char*pszb);
int _stricmpW(const wchar_t* wca, const wchar_t* wcb);
wchar_t* _strcpyW(wchar_t* pszDest, const wchar_t* pszSrc, unsigned int nMax);
void*  _memset(void* pv, int c, unsigned int cb);
void*  _memmove(void* pvDest, const void* pvSrc, unsigned int cb);
#ifdef __cplusplus
}
#endif

#endif