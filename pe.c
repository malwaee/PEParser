#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include "capstone\capstone.h"

#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

LPVOID g_ImageBase;      // A global variable to hold the Image base address
HANDLE hFileMapping = 0; // A handle to the file mapping object

#pragma comment(lib, "capstone")

#define PE_ERROR_VALUE 0

typedef enum
{
    MODE_32, // 32-bit mode
    MODE_64  // 64-bit mode
} arch;

size_t disassemble(PBYTE code, size_t code_size, DWORD64 address, arch mode)
{
    // Input  validation
    if (code && code_size == NULL)
        return 0;

    csh handle;
    cs_insn *insn;
    size_t count;

    PBYTE pCode = code;

    if (mode == MODE_32) // x86 code
    {
        if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
            return -1;
    }

    if (mode == MODE_64) // x64 code
    {
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
            return -1;
    }

    if (address == NULL)
    {
        DWORD64 addr = (DWORD64)code;
        count = cs_disasm(handle, code, code_size, addr, 0, &insn);
    }

    else
        count = cs_disasm(handle, code, code_size, address, 0, &insn);
    if (count > 0)
    {
        int i;
        for (i = 0; i < count; i++)
        {
            printf("\t0x%llX: ", insn[i].address);
            DWORD instructionSize = insn[i].size;
            for (int i = 0; i < instructionSize; i++)
            {
                printf("%X", *pCode);
                ++pCode;
            }

            if (instructionSize < 6)
                printf("\t");

            printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
        }

        if (mode == MODE_32)
            printf("\nx86 code successfully disassembled\n\n");

        if (mode == MODE_64)
            printf("\nx64 code successfully disassembled\n\n");

        cs_free(insn, count);
    }

    else
        printf("Error:Failed to disassemble given code!\n");

    cs_close(&handle);

    return count;
}

// Disassemble a  section
void sectionDisasm(PIMAGE_NT_HEADERS pNth, LPVOID lpImageBase)
{
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNth);
    DWORD NumberOfSections = pNth->FileHeader.NumberOfSections;
    arch mode;

    if (pNth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // 32-bit PE
    {
        printf("x86 code\n");
        mode = MODE_32;
    }

    if (pNth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // 64-bit PE
    {
        printf("x64 code\n");
        mode = MODE_64;
    }

    BYTE sectionName[8];
    BOOL sectionFound = FALSE;

    printf("Available sections are:\n");
    for (int i = 0; i < NumberOfSections; i++)
    {
        printf("\tSection Name: %s\n", pSectionHeader->Name);
        ++pSectionHeader;
    }
    printf("\n");

    printf("Enter the section name you would like to disassemble:\n");
    gets(sectionName);

    pSectionHeader = IMAGE_FIRST_SECTION(pNth); // Reset the section header pointer to point to the first header
    for (int i = 0; i < NumberOfSections; i++)
    {
        if (strncmp(pSectionHeader->Name, sectionName, 8) == 0)
        {
            sectionFound = TRUE;
            const PBYTE data = (PBYTE)lpImageBase + pSectionHeader->PointerToRawData;
            size_t size = pSectionHeader->Misc.VirtualSize;
            DWORD64 address = pSectionHeader->VirtualAddress;
            printf("Disassembling  %s section, VA:0x%X\n\n", sectionName, pSectionHeader->VirtualAddress);
            disassemble(data, size, address, mode);
            break;
        }

        ++pSectionHeader; // go to the next header
    }

    if (!sectionFound)
        printf("Section %s not found!\n", sectionName);
}

void writeHexToFile(PIMAGE_NT_HEADERS pNth, LPVOID lpImageBase, ULONG fileSize)
{
    if (!pNth && !lpImageBase)
    {
        printf("WriteHexToFile:Null arguement exception\n");
        return;
    }

    FILE *pFile;
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNth);
    WORD NumberOfSections = pNth->FileHeader.NumberOfSections;
    BYTE sectionName[8];
    BOOL success = FALSE;
    BOOL nullSection = FALSE;

    char *filename = "hexdump.txt";
    pFile = fopen(filename, "w");

    printf("Available sections are:\n");
    for (int i = 0; i < NumberOfSections; i++) // This first loop is for printing section names
    {
        printf("\tSection Name: %s\n", pSectionHeader->Name);
        ++pSectionHeader; // go to the next header
    }

    printf("\nEnter the section name you wish to dump its bytes (-A for full hexdump):\n");
    gets((char *)sectionName);

    pSectionHeader = IMAGE_FIRST_SECTION(pNth); // Reset the pointer to point to the first header
    for (int i = 0; i < NumberOfSections; i++)
    {
        PBYTE data = (PBYTE)lpImageBase + pSectionHeader->PointerToRawData;
        ULONG size = pSectionHeader->SizeOfRawData;
        if (pFile != NULL && (strncmp(sectionName, pSectionHeader->Name, 8) == 0))
        {
            if (size == 0)
            {
                nullSection = TRUE;
                printf("SizeOfRawData is 0!\n\n");
                break;
            }

            else
            {
                fprintf(pFile, "unsigned char data[%d] = {", size);
                for (int i = 0; i < size; i++)
                {
                    if (i % 16 == 0) // After 16 bytes a new line and a tab, including the first line since 0/16 remainder is 0
                    {
                        fprintf(pFile, "\n\t"); // Newline and a tab after 16 bytes
                    }

                    if (i == (size - 1)) // The last iteration
                    {
                        fprintf(pFile, "0x%02X", data[i]); // The last byte we format without the comma (,)
                        break;
                    }

                    fprintf(pFile, "0x%02X, ", data[i]);
                }

                fprintf(pFile, "\n%s", "};");
                success = TRUE;
                printf("hexdump successfully written to hexdump.txt\n\n");
                break;
            }
        }
        ++pSectionHeader;
    }

    if ((strncmp(sectionName, "-A", 2) == 0) && fileSize != 0)
    {
        PBYTE data = (PBYTE)lpImageBase;
        fprintf(pFile, "unsigned char data[%d] = {", fileSize);
        for (int i = 0; i < fileSize; i++)
        {
            if (i % 16 == 0) // After 16 bytes a new line and a tab, including the first line since 0/16 remainder is 0
            {
                fprintf(pFile, "\n\t");
            }

            if (i == (fileSize - 1)) // The last iteration
            {
                fprintf(pFile, "0x%02X", data[i]); // The last byte we format without the comma (,)
                break;
            }

            fprintf(pFile, "0x%02X, ", data[i]);
        }

        fprintf(pFile, "\n%s", "};");
        success = TRUE;
        printf("hexdump successfully written to hexdump.txt\n\n");
    }

    if (nullSection)
        printf("Nothing to write!\n\n");

    if (!success && !nullSection)
        printf("Uknown section name!\n\n");

    fclose(pFile);
}

static ULONG RvaToOffset3(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize)
{
    PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
    USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
    for (int i = 0; i < NumberOfSections; i++)
    {
        if (psh->VirtualAddress <= Rva)
        {
            if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
            {
                Rva -= psh->VirtualAddress;
                Rva += psh->PointerToRawData;
                return Rva < FileSize ? Rva : 0;
            }
        }
        psh++;
    }
    return 0;
}

void GetExportOffset(const unsigned char *FileData, ULONG FileSize /*const char* ExportName*/)
{
    // Verify DOS Header
    PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)FileData;
    if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("Invalid IMAGE_DOS_SIGNATURE!\r\n");
        return;
    }

    // Verify PE Header
    PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(FileData + pdh->e_lfanew);
    if (pnth->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("Invalid IMAGE_NT_SIGNATURE!\r\n");
        return;
    }

    // Verify Export Directory
    PIMAGE_DATA_DIRECTORY pdd = NULL;
    if (pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        pdd = ((PIMAGE_NT_HEADERS64)pnth)->OptionalHeader.DataDirectory;
    else
        pdd = ((PIMAGE_NT_HEADERS32)pnth)->OptionalHeader.DataDirectory;
    ULONG ExportDirRva = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG ExportDirSize = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    ULONG ExportDirOffset = RvaToOffset3(pnth, ExportDirRva, FileSize);
    if (ExportDirOffset == PE_ERROR_VALUE)
    {
        printf("Invalid Export Directory!\r\n");
        return;
    }

    // Read Export Directory
    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirOffset);
    ULONG NumberOfNames = ExportDir->NumberOfNames;
    ULONG AddressOfFunctionsOffset = RvaToOffset3(pnth, ExportDir->AddressOfFunctions, FileSize);
    ULONG AddressOfNameOrdinalsOffset = RvaToOffset3(pnth, ExportDir->AddressOfNameOrdinals, FileSize);
    ULONG AddressOfNamesOffset = RvaToOffset3(pnth, ExportDir->AddressOfNames, FileSize);
    if (AddressOfFunctionsOffset == PE_ERROR_VALUE ||
        AddressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
        AddressOfNamesOffset == PE_ERROR_VALUE)
    {
        printf("[Invalid Export Directory Contents!\r\n");
        return;
    }
    ULONG *AddressOfFunctions = (ULONG *)(FileData + AddressOfFunctionsOffset);
    USHORT *AddressOfNameOrdinals = (USHORT *)(FileData + AddressOfNameOrdinalsOffset);
    ULONG *AddressOfNames = (ULONG *)(FileData + AddressOfNamesOffset);

    // Find Export
    // ULONG ExportOffset = PE_ERROR_VALUE;
    for (ULONG i = 0; i < NumberOfNames; i++)
    {
        ULONG CurrentNameOffset = RvaToOffset3(pnth, AddressOfNames[i], FileSize);
        if (CurrentNameOffset == PE_ERROR_VALUE)
            continue;
        const char *CurrentName = (const char *)(FileData + CurrentNameOffset);
        printf("\t\tName:%s\n", CurrentName);
        ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
        if (CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
            continue; // we ignore forwarded exports
        /*if(!strcmp(CurrentName, ExportName))  //compare the export name to the requested export
        {
            ExportOffset = RvaToOffset3(pnth, CurrentFunctionRva, FileSize);
            break;
        }*/
    }

    /*if(ExportOffset == PE_ERROR_VALUE)
    {
        printf("[TITANHIDE] Export %s not found in export table!\r\n");
    }*/

    return;
}

// convert virtual address to File offset
DWORD Rva2Offset(DWORD va, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
    size_t i = 0;
    PIMAGE_SECTION_HEADER pSeh;
    if (va == 0)
    {
        return (va);
    }

    pSeh = psh;
    for (i = 0; i < pnt->FileHeader.NumberOfSections; ++i)
    {
        // if the virtual address falls between this sections address space
        if (va >= pSeh->VirtualAddress && va < pSeh->VirtualAddress + pSeh->Misc.VirtualSize)
        {
            break;
        }
        ++pSeh;
    }
    return (va - pSeh->VirtualAddress + pSeh->PointerToRawData); // the file offset within the section
}

DWORD Rva2Offset2(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if (dwRva < pSectionHeader[0].PointerToRawData)
        return dwRva;

    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
    {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
            return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
    }

    return 0;
}

PIMAGE_DOS_HEADER parseDosHeader(LPVOID lpImageBase, BOOL display)
{
    if (!lpImageBase)
    {
        printf("Null pointer: Image Base\n");
        return NULL;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImageBase;
    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        if (display)
        {
            // parse the DOS Header
            printf("\t\t[DOS  HEADER]\n\n");
            printf("\t\tMagic Number:\t0x%X\n", pDosHeader->e_magic);
            printf("\t\tBytes on last page of File:\t%hu\n", pDosHeader->e_cblp);
            printf("\t\tPages in File:\t0x%X\n", pDosHeader->e_cp);
            printf("\t\tRelocations:\t0x%X\n", pDosHeader->e_crlc);
            printf("\t\tSize of header in paragraphs:\t0x%X\n", pDosHeader->e_cparhdr);
            printf("\t\tMinimum extra paragraphs needed:\t0x%X\n", pDosHeader->e_minalloc);
            printf("\t\tMaximum extra paragraphs needed:\t0x%X\n", pDosHeader->e_maxalloc);
            printf("\t\tInitial (relative) SS value:\t0x%X\n", pDosHeader->e_ss);
            printf("\t\tInitial SP value:\t0x%X\n", pDosHeader->e_sp);
            printf("\t\tChecksum:\t0x%X\n", pDosHeader->e_csum);
            printf("\t\tInitial IP value:\t0x%X\n", pDosHeader->e_ip);
            printf("\t\tInitial (relative) CS value:\t0x%X\n", pDosHeader->e_cs);
            printf("\t\tFile address of the relocation table:\t0x%X\n", pDosHeader->e_lfarlc);
            printf("\t\tOverlay number:\t0x%X\n", pDosHeader->e_ovno);
            printf("\t\tReserved words:\t");
            for (int i = 0; i < 4; ++i)
            {
                printf("%X", pDosHeader->e_res[i]);
            }
            printf("\n");
            printf("\t\tOEM identifier:\t%X\n", pDosHeader->e_oemid);
            printf("\t\tOEM information:\t%X\n", pDosHeader->e_oeminfo);
            printf("\t\tReserved words 2:\t");
            for (int i = 0; i < 10; ++i)
            {
                printf("%X", pDosHeader->e_res2[i]);
            }
            printf("\n");
            printf("\t\tFile address of the new exe header:\t0x%X\n\n", pDosHeader->e_lfanew);
        }

        return pDosHeader;
    }

    printf("Image Dos signature not found!\n");
    return NULL;
}

PIMAGE_NT_HEADERS parseNtHeaders(LPVOID lpImageBase, PIMAGE_DOS_HEADER pDosHeader, BOOL display)
{
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)lpImageBase + pDosHeader->e_lfanew);
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNTHeaders->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNTHeaders->OptionalHeader;
    if (pNTHeaders->Signature == IMAGE_NT_SIGNATURE)
    {
        if (display)
        {
            // parse NT headers
            printf("\t\t[NT  HEADERS]\n\n");
            // Image File Header
            printf("\t\t[FILE  HEADER]\n\n");
            printf("\t\tMachine:\t0x%X\n", pFileHeader->Machine);
            printf("\t\tNumberOfSections:\t%hu\n", pFileHeader->NumberOfSections);
            printf("\t\tTimeDateStamp:\t0x%X\n", pFileHeader->TimeDateStamp);
            printf("\t\tPointerToSymbolTable:\t0x%X\n", pFileHeader->PointerToSymbolTable);
            printf("\t\tNumberOfSymbols:\t%d\n", pFileHeader->NumberOfSymbols);
            printf("\t\tSizeOfOptionalHeader:\t0x%X\n", pFileHeader->SizeOfOptionalHeader);
            printf("\t\tCharacteristics:\t0x%X\n\n", pFileHeader->Characteristics);

            // Optional Header
            printf("\t\t[OPTIONAL  HEADER]\n\n");
            printf("\t\tMagic:\t0x%X\n", pOptionalHeader->Magic);
            printf("\t\tMajorLinkerVersion:\t0x%X\n", pOptionalHeader->MajorLinkerVersion);
            printf("\t\tMinorLinkerVersion:\t0x%X\n", pOptionalHeader->MinorLinkerVersion);
            printf("\t\tSizeOfCode:\t0x%X\n", pOptionalHeader->SizeOfCode);
            printf("\t\tSizeOfInitializedData:\t0x%X\n", pOptionalHeader->SizeOfInitializedData);
            printf("\t\tSizeOfUnitializedData:\t0x%X\n", pOptionalHeader->SizeOfUninitializedData);
            printf("\t\tAddressOfEntryPoint:\t0x%X\n", pOptionalHeader->AddressOfEntryPoint);
            printf("\t\tBaseOfCode:\t0x%X\n", pOptionalHeader->BaseOfCode);
            printf("\t\tImageBase:\t0x%llX\n", pOptionalHeader->ImageBase);
            printf("\t\tSectionAlignment:\t%d\n", pOptionalHeader->SectionAlignment);
            printf("\t\tFileAlignment:\t%d\n", pOptionalHeader->FileAlignment);
            printf("\t\tMajorOperatingSystemVersion:\t%hu\n", pOptionalHeader->MajorOperatingSystemVersion);
            printf("\t\tMinorOperatingSystemVersion:\t%hu\n", pOptionalHeader->MinorOperatingSystemVersion);
            printf("\t\tMajorImageVersion:\t%hu\n", pOptionalHeader->MajorImageVersion);
            printf("\t\tMinorImageVersion:\t%hu\n", pOptionalHeader->MinorImageVersion);
            printf("\t\tMajorSubsystemVersion:\t%hu\n", pOptionalHeader->MajorSubsystemVersion);
            printf("\t\tMinorSubsystemVersion:\t%hu\n", pOptionalHeader->MinorSubsystemVersion);
            printf("\t\tWin32VersionValue:\t%d\n", pOptionalHeader->Win32VersionValue);
            printf("\t\tSizeOfImage:\t%d\n", pOptionalHeader->SizeOfImage);
            printf("\t\tSizeOfHeaders:\t%d\n", pOptionalHeader->SizeOfHeaders);
            printf("\t\tCheckSum:\t0x%X\n", pOptionalHeader->CheckSum);
            printf("\t\tSubsystem:\t%hu\n", pOptionalHeader->Subsystem);
            printf("\t\tDllCharacteristics:\t0x%X\n", pOptionalHeader->DllCharacteristics);
            printf("\t\tSizeOfStackReserve:\t0x%llX\n", pOptionalHeader->SizeOfStackReserve);
            printf("\t\tSizeOfStackCommit:\t0x%llX\n", pOptionalHeader->SizeOfStackCommit);
            printf("\t\tSizeOfHeapReserve:\t0x%llX\n", pOptionalHeader->SizeOfHeapReserve);
            printf("\t\tSizeOfHeapCommit:\t0x%llX\n", pOptionalHeader->SizeOfHeapCommit);
            printf("\t\tLoaderFlags:\t0x%X\n", pOptionalHeader->LoaderFlags);
            printf("\t\tNumberOfRvaAndSizes:\t%d\n\n", pOptionalHeader->NumberOfRvaAndSizes);
            // IMAGE_DATA_DIRECTORY[];
            printf("\t\t[IMAGE  DATA  DIRECTORY]\n\n");
            printf("\t\tExport Directory:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
            printf("\t\tImport Directory:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
            printf("\t\tResource Directory:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
            printf("\t\tException Directory:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
            printf("\t\tSecurity Directory:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
            printf("\t\tBase Relocation Table:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
            printf("\t\tDebug Directory:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
            printf("\t\tArchitecture Specific Data:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
            printf("\t\tRVA Of GP:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
            printf("\t\tTLS Directory\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
            printf("\t\tLoad Configuration Directory\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
            printf("\t\tBound Import Directory:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
            printf("\t\tImport Address Table:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
            printf("\t\tDelay Load Import Descriptors:\tAddress:0x%X\tSize:%d\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
            printf("\t\tCOM Runtime Descriptor:\tAddress:0x%X\tSize:%d\n\n", pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress, pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);
        }

        return pNTHeaders;
    }

    printf("Image NT Signature not found!\n");
    return NULL;
}

PIMAGE_SECTION_HEADER parseSectionHeaders(PIMAGE_NT_HEADERS pNth, LPVOID lpImageBase, BOOL display)
{
    PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNth);
    WORD NumberOfSections = pNth->FileHeader.NumberOfSections;
    // parse Section Headers
    if (display)
    {
        printf("\t\t[SECTIONS  HEADERS]\n\n");
        for (int i = 0; i < NumberOfSections; ++i)
        {
            printf("\t\tSection Name:\t%s\n", pSectionHeaders->Name);
            printf("\t\tPhysicalAddress:\t%d\n", pSectionHeaders->Misc.PhysicalAddress);
            printf("\t\tVirtualSize:\t%d\n", pSectionHeaders->Misc.VirtualSize);
            printf("\t\tVirtualAddress:\t0x0000%X\n", pSectionHeaders->VirtualAddress);
            printf("\t\tSizeOfRawData:\t%d\n", pSectionHeaders->SizeOfRawData);
            printf("\t\tPointerToRawData:\t%d\n", pSectionHeaders->PointerToRawData);
            printf("\t\tPointerToRelocations:\t%d\n", pSectionHeaders->PointerToRelocations);
            printf("\t\tNumberOfRelocations:\t%hu\n", pSectionHeaders->NumberOfRelocations);
            printf("\t\tNumberOfLineNumbers:\t%hu\n", pSectionHeaders->NumberOfLinenumbers);
            printf("\t\tCharacteristics:\t0x%X\n\n", pSectionHeaders->Characteristics);
            printf("\n\n");
            ++pSectionHeaders;
        }
    }

    return pSectionHeaders;
}

void parseImports(LPVOID lpImageBase, PIMAGE_NT_HEADERS pNth)
{
    // parse the import directory
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNth->OptionalHeader;
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNth->FileHeader;
    printf("\t\t[DLL IMPORTS]\n\n");
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0) // if size is 0 import table does not exist
    {
        pSectionHeaders = IMAGE_FIRST_SECTION(pNth);
        pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpImageBase + Rva2Offset(
                                                                                    pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSectionHeaders, pNth));

        LPSTR libname[256];
        size_t i = 0;
        // loop until you reach an empty IMAGE_IMPORT_DESCRIPTOR
        while (pImportDescriptor->Name)
        {
            printf("\t\tCharacteristics:\t0x%X\n", pImportDescriptor->Characteristics);
            printf("\t\tOriginalFirstThunk:\t0x%X\n", pImportDescriptor->OriginalFirstThunk);
            printf("\t\tTimeDateStamp:\t0x%X\n", pImportDescriptor->TimeDateStamp);
            printf("\t\tForwarder Chain:\t0x%X\n", pImportDescriptor->ForwarderChain);
            printf("\t\tName Address:\t0x%X\n", pImportDescriptor->Name);
            printf("\t\tFirstThunk:\t0x%X\n", pImportDescriptor->FirstThunk);
            printf("\t\tLibrary Name:");
            // Get the name of each DLL
            libname[i] = (PCHAR)((DWORD_PTR)lpImageBase + Rva2Offset(pImportDescriptor->Name, pSectionHeaders,
                                                                     pNth));
            printf("\t%s\n", libname[i]);

            // Address of names
            /* start adress of names in look up table from import table name RVA */
            BYTE *name = 0;
            WORD ordinal = 0;
            int CellSize = 0;
            // for PE32+ ...4 for PE32
            if (pFileHeader->Machine == IMAGE_FILE_MACHINE_I386)
            {
                CellSize = 4;
            }

            if (pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64)
            {
                CellSize = 8;
            }

            char *cell = (char *)lpImageBase + ((pImportDescriptor->OriginalFirstThunk) ? Rva2Offset(pImportDescriptor->OriginalFirstThunk, pSectionHeaders, pNth)
                                                                                        : Rva2Offset(pImportDescriptor->FirstThunk, pSectionHeaders, pNth));

            /* while names in look up table */
            for (;; cell += CellSize) // Import Name Table is an array of DWORD(PE32) or DWORD64(PE32+)
            {
                DWORD64 rva = 0;

                /* break if rva = 0 */
                memcpy(&rva, cell, CellSize); // Copy the DWORD64 value to rva
                if (!rva)
                    break;

                /* if rva > 0 function was imported by name. if rva < 0 function was imported by ordinal */
                if (rva > 0)
                {
                    name = (BYTE *)((BYTE *)lpImageBase + Rva2Offset(rva, pSectionHeaders, pNth) + 2);
                    printf("\t\tImported function name:\t%s\n", name);
                }
                else
                {
                    ordinal = (WORD)(rva & 0xFFFF);
                    printf("\t\tOrdinal:%hu\n", ordinal);
                }
            }
            printf("\n\n");
            ++pImportDescriptor;
            ++i;
        };
        printf("\n\n");
    }
    else
    {
        printf("\t\tNo Import Table found!\n");
        printf("\t\tIMAGE_DIRECTORY_IMPORT size is 0!\n\n");
    }
}

void parseExports(PIMAGE_NT_HEADERS pNth, LPVOID lpImageBase, ULONG fileSize)
{
    // parse the export directory
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNth->FileHeader;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNth->OptionalHeader;
    // if (pFileHeader->Characteristics & IMAGE_FILE_DLL) - Some executables export functions decided to remove this e.g ntoskrnl.exe
    if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0) // if size is 0 export table does not exist
    {
        printf("\t\t[DLL EXPORTS]\n\n");
        GetExportOffset((byte *)lpImageBase, fileSize);
    }

    else
    {
        printf("No Export Table found!\n\n");
        printf("IMAGE_DIRECTORY_ENTRY_EXPORT size is 0!\n\n");
    }
    printf("\n");
}

void printSectionBytes(PIMAGE_NT_HEADERS pNth, LPVOID lpImageBase)
{
    PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNth);
    WORD NumberOfSections = pNth->FileHeader.NumberOfSections;
    BYTE sectionName[8];
    BOOL sectionFound = FALSE;

    if (pNth != NULL && lpImageBase != NULL) // Input validation
    {
        printf("Available sections are:\n");
        for (int i = 0; i < NumberOfSections; i++) // This first loop is for printing section names
        {
            printf("\tSection Name: %s\n", pSectionHeaders->Name);
            ++pSectionHeaders; // go to the next header
        }

        printf("\nEnter the section name you want to display its bytes:\n");
        gets((char *)sectionName);

        pSectionHeaders = IMAGE_FIRST_SECTION(pNth); // Reset the pointer to section headers to point to the first header
        // Print each section bytes
        printf("%s section bytes:\n\n", sectionName);
        for (int i = 0; i < NumberOfSections; i++) // This second loop is for iterating each section header to compare if sectionName matches with pSectionHeaders->Name
        {
            // If sectionName matches with one of the Section Name, display its byte contents
            if (strncmp((const char *)pSectionHeaders->Name, sectionName, strlen(sectionName)) == 0)
            {
                sectionFound = TRUE;

                if (pSectionHeaders->SizeOfRawData == 0)
                {
                    printf("SizeOfRawData is 0!\n\n");
                    break;
                }

                const BYTE *p = (BYTE *)lpImageBase + pSectionHeaders->PointerToRawData;
                const BYTE *pEnd = p + pSectionHeaders->SizeOfRawData;

                while (p < pEnd) // This third loop is for displaying section bytes
                {
                    printf("%02X", *p);
                    ++p;
                }
                printf("\r\n\n");
                break;
            }
            ++pSectionHeaders; // go to the next header
        }

        if (sectionFound == FALSE)
        {
            printf("Section %s is not present!\n\n", sectionName);
        }
    }
}

LPVOID mapFile(HANDLE hFile)
{
    LPVOID pImageBase;

    if (hFile == INVALID_HANDLE_VALUE) // Input validation
        return (LPVOID)1;

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMapping == 0)
    {
        printf("CreateFileMapping failed\n\n");
        CloseHandle(hFile);
        return (LPVOID)1;
    }

    pImageBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (pImageBase == 0)
    {
        printf("MapViewOfFile failed\n\n");
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return (LPVOID)1;
    }

    return pImageBase;
}

void cleanUp(HANDLE hFile, HANDLE hFileMapping, LPVOID lpImageBase)
{
    UnmapViewOfFile(lpImageBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}

void parsePE()
{
    HANDLE hFile = 0;
    BYTE fileName[MAX_PATH];
    BYTE argument[10];
    ULONG fileSize;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNTHeaders;
    PIMAGE_SECTION_HEADER pSectionHeader;

    printf("PE File Format Parser with an Intergrated Disassembler (v1.2, Jan 03 2024)\nCopyright  (C) 2023-2024 Harry Kibet Kemboi\nAll Rights Reserved.\n\n");
    for (;;)
    {
    LABEL1:
        printf("Enter the full path of filename to parse:\n");
        gets((char *)fileName);

        hFile = CreateFileA((LPCSTR)fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf("Error opening %s\nEnter a valid path!\n\n", fileName);
            goto LABEL1;
        }

        fileSize = GetFileSize(hFile, NULL);
        g_ImageBase = mapFile(hFile);
        if (g_ImageBase != NULL)
        {
            // Initialize the necessary headers first without displaying them
            pDosHeader = parseDosHeader(g_ImageBase, FALSE);
            pNTHeaders = parseNtHeaders(g_ImageBase, pDosHeader, FALSE);
            pSectionHeader = parseSectionHeaders(pNTHeaders, g_ImageBase, FALSE);

            printf("What would you like to parse?\n\t-D for Dos Header\n\t-N for NT Headers\n\t-S for Sections Headers\n\t-I for Import Table\n\t-E for Export Table\n\t-A for parsing all headers and data directories\n\t-P for displaying bytes of a section\n\t-Hex to dump section bytes or full hexdump\n\t-Dis to disassemble a section\n\t-M to map and parse a new file\n\t-Exit to quit the program\n\n");
        LABEL2:
            printf("PEParser> ");
            gets((char *)argument);

            if (strncmp(argument, "-D", sizeof(argument)) == 0)
            {
                pDosHeader = parseDosHeader(g_ImageBase, TRUE);
            }

            else if (strncmp(argument, "-N", sizeof(argument)) == 0)
            {
                pNTHeaders = parseNtHeaders(g_ImageBase, pDosHeader, TRUE);
            }

            else if (strncmp(argument, "-S", sizeof(argument)) == 0)
            {
                pSectionHeader = parseSectionHeaders(pNTHeaders, g_ImageBase, TRUE);
            }

            else if (strncmp(argument, "-I", sizeof(argument)) == 0)
            {
                parseImports(g_ImageBase, pNTHeaders);
            }

            else if (strncmp(argument, "-E", sizeof(argument)) == 0)
            {
                parseExports(pNTHeaders, g_ImageBase, fileSize);
            }

            else if (strncmp(argument, "-P", sizeof(argument)) == 0)
            {
                printSectionBytes(pNTHeaders, g_ImageBase);
            }

            else if (strncmp(argument, "-A", sizeof(argument)) == 0)
            {
                pDosHeader = parseDosHeader(g_ImageBase, TRUE);
                pNTHeaders = parseNtHeaders(g_ImageBase, pDosHeader, TRUE);
                pSectionHeader = parseSectionHeaders(pNTHeaders, g_ImageBase, TRUE);
                parseImports(g_ImageBase, pNTHeaders);
                parseExports(pNTHeaders, g_ImageBase, fileSize);
            }

            else if (strncmp(argument, "-Hex", sizeof(argument)) == 0)
            {
                writeHexToFile(pNTHeaders, g_ImageBase, fileSize);
            }

            else if (strncmp(argument, "-Dis", sizeof(argument)) == 0)
            {
                sectionDisasm(pNTHeaders, g_ImageBase);
            }

            else if (strncmp(argument, "-H", sizeof(argument)) == 0)
            {
                printf("\t-D for Dos Header\n\t-N for NT Headers\n\t-S for Sections Headers\n\t-I for Import Table\n\t-E for Export Table\n\t-A for parsing all headers and data directories\n\t-P for displaying bytes of a section\n\t-Hex to dump section bytes or full hexdump\n\t-Dis to disassemble a section\n\t-H to display this help message\n\t-M to map and parse a new file\n\t-Exit to quit the program\n\n");
            }

            else if (strncmp(argument, "-M", sizeof(argument)) == 0)
            {
                cleanUp(hFile, hFileMapping, g_ImageBase);
                goto LABEL1;
            }

            else if (strncmp(argument, "-Exit", sizeof(argument)) == 0 || strncmp(argument, "exit", sizeof(argument)) == 0)
            {
                cleanUp(hFile, hFileMapping, g_ImageBase);
                ExitProcess(0);
            }

            else
                printf("Unsupported argument!\nEnter -H to display help message\n\n");

            ZeroMemory(argument, sizeof(argument));
            goto LABEL2;
        }
        ZeroMemory(fileName, MAX_PATH);
        cleanUp(hFile, hFileMapping, g_ImageBase);
        return;
    }
}

int main()
{
    parsePE();
    return 0;
}