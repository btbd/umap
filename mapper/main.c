#include "stdafx.h"

INT64(*HalDispatchOriginal)(PVOID, PVOID);

VOID Main(PVOID func) {
	// The bootkit mapper will fill this data
	static volatile BYTE mapperData[MAPPER_DATA_SIZE] = { 0x12, 0x34, 0x56, 0x78, 0x90 };

	// Undo hook by bootkit (no error checking because there's no reason it should fail
	// and if it does fail then you can't recover)
	MemCopyWP(func, (PVOID)mapperData, sizeof(mapperData));

	// Simple .data function pointer hook
	PVOID kernelBase = GetModuleBaseAddress("ntoskrnl.exe");
	if (!kernelBase) {
		printf("Failed to find kernel base\n");
		return;
	}

	PVOID addr = FindPatternImage(kernelBase, "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\x85\xC0\x78\x40", "xxx????x????xxxxxx");
	if (!addr) {
		printf("Failed to find the function pointer\n");
		return;
	}

	*(PVOID *)&HalDispatchOriginal = InterlockedExchangePointer(RELATIVE_ADDR(addr, 7), (PVOID)HalDispatchHook);
}

INT64 HalDispatchHook(PIMAGE_DATA imageData, PINT64 outStatus) {
	if (ExGetPreviousMode() != UserMode || !imageData) {
		return HalDispatchOriginal(imageData, outStatus);
	}

	IMAGE_DATA safeData;
	if (!SafeCopy(&safeData, imageData, sizeof(safeData)) || safeData.Magic != 0x6789) {
		return HalDispatchOriginal(imageData, outStatus);
	}

	PVOID kernelBuffer = ExAllocatePool(NonPagedPool, safeData.Length);
	if (!kernelBuffer) {
		*outStatus = STATUS_NO_MEMORY;
		return STATUS_SUCCESS;
	}

	if (!SafeCopy(kernelBuffer, &imageData->Buffer, safeData.Length)) {
		ExFreePool(kernelBuffer);
		*outStatus = STATUS_ACCESS_VIOLATION;
		return STATUS_SUCCESS;
	}

	CHAR error[0xFF] = { 0 };
	NTSTATUS status = MapImage(kernelBuffer, error);
	SafeCopy(&imageData->Buffer, error, strlen(error) + 1);
	ExFreePool(kernelBuffer);

	*outStatus = status;
	return STATUS_SUCCESS;
}

// One could easily pass a bogus PE to intentionally BSOD - CBA to make it safe
NTSTATUS MapImage(PBYTE buffer, PCHAR error) {
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)buffer;
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
		sprintf(error, "Image does not have DOS signature");
		return STATUS_NOT_SUPPORTED;
	}

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeaders->e_lfanew);

	PBYTE base = ExAllocatePool(NonPagedPoolExecute, ntHeaders->OptionalHeader.SizeOfImage);
	if (!base) {
		sprintf(error, "Failed to allocate pool of size 0x%X", ntHeaders->OptionalHeader.SizeOfImage);
		return STATUS_NO_MEMORY;
	}

	// Map headers
	memcpy(base, buffer, ntHeaders->OptionalHeader.SizeOfHeaders);

	// Map sections
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((PBYTE)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
	for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (section->SizeOfRawData) {
			memcpy(base + section->VirtualAddress, buffer + section->PointerToRawData, section->SizeOfRawData);
		}
	}

	// Resolve imports
	ULONG importsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (importsRva) {
		PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + importsRva);

		for (; importDescriptor->FirstThunk; ++importDescriptor) {
			PCHAR moduleName = (PCHAR)(base + importDescriptor->Name);
			PVOID module = GetModuleBaseAddress(moduleName);
			if (!module) {
				sprintf(error, "Failed to find module %s", moduleName);

				ExFreePool(base);
				return STATUS_NOT_FOUND;
			}

			PIMAGE_THUNK_DATA64 thunk = (PIMAGE_THUNK_DATA64)(base + importDescriptor->FirstThunk);
			PIMAGE_THUNK_DATA64 thunkOriginal = (PIMAGE_THUNK_DATA64)(base + importDescriptor->OriginalFirstThunk);

			for (; thunk->u1.AddressOfData; ++thunk, ++thunkOriginal) {
				PCHAR importName = ((PIMAGE_IMPORT_BY_NAME)(base + thunkOriginal->u1.AddressOfData))->Name;
				ULONG64 import = GetExport(module, importName);
				if (!import) {
					sprintf(error, "Failed to find export %s in module %s", importName, moduleName);

					ExFreePool(base);
					return STATUS_NOT_FOUND;
				}

				thunk->u1.Function = import;
			}
		}
	}

	// Resolve relocations
	PIMAGE_DATA_DIRECTORY baseRelocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (baseRelocDir->VirtualAddress) {
		PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(base + baseRelocDir->VirtualAddress);

		for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size; ) {
			ULONG relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			PUSHORT relocData = (PUSHORT)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
			PBYTE relocBase = base + reloc->VirtualAddress;

			for (UINT32 i = 0; i < relocCount; ++i, ++relocData) {
				USHORT data = *relocData;
				USHORT type = data >> 12;
				USHORT offset = data & 0xFFF;

				switch (type) {
					case IMAGE_REL_BASED_ABSOLUTE:
						break;
					case IMAGE_REL_BASED_DIR64: {
						PULONG64 rva = (PULONG64)(relocBase + offset);
						*rva = (ULONG64)(base + (*rva - ntHeaders->OptionalHeader.ImageBase));
						break;
					}
					default:
						sprintf(error, "Unsupported relocation type %d", type);

						ExFreePool(base);
						return STATUS_NOT_SUPPORTED;
				}
			}

			currentSize += reloc->SizeOfBlock;
			reloc = (PIMAGE_BASE_RELOCATION)relocData;
		}
	}

	return ((PDRIVER_INITIALIZE)(base + ntHeaders->OptionalHeader.AddressOfEntryPoint))((PDRIVER_OBJECT)base, NULL);
}

// The third parameter is a pointer to the original DriverEntry that we inline hooked
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registryPath, DRIVER_INITIALIZE func) {
	UNREFERENCED_PARAMETER(driver);
	UNREFERENCED_PARAMETER(registryPath);

	Main((PVOID)func);

	return func(driver, registryPath);
}