#pragma once

#define SEC_TO_MICRO(s) ((s) * 1000000)
#define RELATIVE_ADDR(addr, size) ((VOID *)((UINT8 *)(addr) + *(INT32 *)((UINT8 *)(addr) + ((size) - (INT32)sizeof(INT32))) + (size)))
#define CONTAINING_RECORD(address, type, field) ((type *)((UINT8 *)(address) - (UINTN)(&((type *)0)->field)))

#define JMP_SIZE (14)

#define IMAGE_REL_BASED_DIR64 (10)
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES (16)
#define IMAGE_SIZEOF_SHORT_NAME (8)
#define IMAGE_DIRECTORY_ENTRY_EXPORT (0)
#define IMAGE_DIRECTORY_ENTRY_IMPORT (1)
#define IMAGE_DIRECTORY_ENTRY_BASERELOC (5)
#define IMAGE_DOS_SIGNATURE (0x5A4D)

typedef enum _BL_ARCH_MODE {
    BlProtectedMode = 0,
    BlRealMode
} BL_ARCH_MODE;

#define BL_MEMORY_TYPE_APPLICATION (0xE0000012)
#define BL_MEMORY_ATTRIBUTE_RWX (0x424000)

typedef struct _UNICODE_STRING {
    UINT16 Length;
    UINT16 MaximumLength;
    CHAR16 *Buffer;
} UNICODE_STRING;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    VOID *ExceptionTable;
    UINT32 ExceptionTableSize;
    VOID *GpValue;
    VOID *NonPagedDebugInfo;
    VOID *ImageBase;
    VOID *EntryPoint;
    UINT32 SizeOfImage;
    UNICODE_STRING FullImageName;
    UNICODE_STRING BaseImageName;
} KLDR_DATA_TABLE_ENTRY;

typedef struct _LOADER_PARAMETER_BLOCK {
    UINT32 OsMajorVersion;
    UINT32 OsMinorVersion;
    UINT32 Size;
    UINT32 OsLoaderSecurityVersion;
    LIST_ENTRY LoadOrderListHead;
} LOADER_PARAMETER_BLOCK;

typedef struct _ALPCP_LIST_ENTRY {
    LIST_ENTRY Entry;
    VOID *Callback;
} ALPCP_LIST_ENTRY;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    UINT16 e_magic;                     // Magic number
    UINT16 e_cblp;                      // Bytes on last page of file
    UINT16 e_cp;                        // Pages in file
    UINT16 e_crlc;                      // Relocations
    UINT16 e_cparhdr;                   // Size of header in paragraphs
    UINT16 e_minalloc;                  // Minimum extra paragraphs needed
    UINT16 e_maxalloc;                  // Maximum extra paragraphs needed
    UINT16 e_ss;                        // Initial (relative) SS value
    UINT16 e_sp;                        // Initial SP value
    UINT16 e_csum;                      // Checksum
    UINT16 e_ip;                        // Initial IP value
    UINT16 e_cs;                        // Initial (relative) CS value
    UINT16 e_lfarlc;                    // File address of relocation table
    UINT16 e_ovno;                      // Overlay number
    UINT16 e_res[4];                    // Reserved words
    UINT16 e_oemid;                     // OEM identifier (for e_oeminfo)
    UINT16 e_oeminfo;                   // OEM information; e_oemid specific
    UINT16 e_res2[10];                  // Reserved words
    UINT32 e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    UINT32   VirtualAddress;
    UINT32   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    UINT16               Magic;
    UINT8                MajorLinkerVersion;
    UINT8                MinorLinkerVersion;
    UINT32               SizeOfCode;
    UINT32               SizeOfInitializedData;
    UINT32               SizeOfUninitializedData;
    UINT32               AddressOfEntryPoint;
    UINT32               BaseOfCode;
    UINT64               ImageBase;
    UINT32               SectionAlignment;
    UINT32               FileAlignment;
    UINT16               MajorOperatingSystemVersion;
    UINT16               MinorOperatingSystemVersion;
    UINT16               MajorImageVersion;
    UINT16               MinorImageVersion;
    UINT16               MajorSubsystemVersion;
    UINT16               MinorSubsystemVersion;
    UINT32               Win32VersionValue;
    UINT32               SizeOfImage;
    UINT32               SizeOfHeaders;
    UINT32               CheckSum;
    UINT16               Subsystem;
    UINT16               DllCharacteristics;
    UINT64               SizeOfStackReserve;
    UINT64               SizeOfStackCommit;
    UINT64               SizeOfHeapReserve;
    UINT64               SizeOfHeapCommit;
    UINT32               LoaderFlags;
    UINT32               NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER {
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
    UINT32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    UINT8    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        UINT32   PhysicalAddress;
        UINT32   VirtualSize;
    } Misc;
    UINT32   VirtualAddress;
    UINT32   SizeOfRawData;
    UINT32   PointerToRawData;
    UINT32   PointerToRelocations;
    UINT32   PointerToLinenumbers;
    UINT16   NumberOfRelocations;
    UINT16   NumberOfLinenumbers;
    UINT32   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#pragma warning(push)
#pragma warning(disable: 4201)
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        UINT32   Characteristics;
        UINT32   OriginalFirstThunk;
    };

    UINT32   TimeDateStamp;
    UINT32   ForwarderChain;
    UINT32   Name;
    UINT32   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
#pragma warning(pop)

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        UINT64 ForwarderString;
        UINT64 Function;
        UINT64 Ordinal;
        UINT64 AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64;

typedef struct _IMAGE_IMPORT_BY_NAME {
    UINT16 Hint;
    CHAR8  Name[1];
} IMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    UINT32 Characteristics;
    UINT32 TimeDateStamp;
    UINT16 MajorVersion;
    UINT16 MinorVersion;
    UINT32 Name;
    UINT32 Base;
    UINT32 NumberOfFunctions;
    UINT32 NumberOfNames;
    UINT32 AddressOfFunctions;
    UINT32 AddressOfNames;
    UINT32 AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_BASE_RELOCATION {
    UINT32 VirtualAddress;
    UINT32 SizeOfBlock;
} IMAGE_BASE_RELOCATION;

VOID MemCopy(VOID *dest, VOID *src, UINTN size);
VOID *FindPattern(CHAR8 *base, UINTN size, CHAR8 *pattern, CHAR16 *mask);
VOID *TrampolineHook(VOID *dest, VOID *src, UINT8 original[JMP_SIZE]);
VOID TrampolineUnHook(VOID *src, UINT8 original[JMP_SIZE]);
KLDR_DATA_TABLE_ENTRY *GetModuleEntry(LIST_ENTRY *list, CHAR16 *name);
UINT64 GetExport(UINT8 *base, CHAR8 *export);