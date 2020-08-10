#include "stdafx.h"

BOOLEAN SafeCopy(PVOID dest, PVOID src, SIZE_T size) {
	SIZE_T returnSize = 0;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, PsGetCurrentProcess(), dest, size, KernelMode, &returnSize)) && returnSize == size) {
		return TRUE;
	}

	return FALSE;
}

BOOLEAN CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if (*mask == 'x' && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask) {
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i) {
		PVOID addr = &base[i];
		if (CheckMask(addr, pattern, mask)) {
			return addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask) {
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, ".text", 5) == 0) {
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match) {
				break;
			}
		}
	}

	return match;
}

PVOID GetModuleBaseAddress(PCHAR name) {
	PVOID addr = 0;

	ULONG size = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		printf("ZwQuerySystemInformation for size failed: %x\n", status);
		return addr;
	}

	PSYSTEM_MODULE_INFORMATION modules = ExAllocatePool(NonPagedPool, size);
	if (!modules) {
		printf("Failed to allocate %d bytes for modules\n", size);
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		printf("ZwQuerySystemInformation failed: %x\n", status);

		ExFreePool(modules);
		return addr;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		SYSTEM_MODULE m = modules->Modules[i];

		if (strstr((PCHAR)m.FullPathName, name)) {
			addr = m.ImageBase;
			break;
		}
	}

	ExFreePool(modules);
	return addr;
}

ULONG64 GetExport(PBYTE base, PCHAR export) {
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)base;
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(base + dosHeaders->e_lfanew);

	ULONG exportsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportsRva) {
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exportsRva);
	PULONG nameRva = (PULONG)(base + exports->AddressOfNames);

	for (ULONG i = 0; i < exports->NumberOfNames; ++i) {
		PCHAR func = (PCHAR)(base + nameRva[i]);
		if (strcmp(func, export) == 0) {
			PULONG funcRva = (PULONG)(base + exports->AddressOfFunctions);
			PWORD ordinalRva = (PWORD)(base + exports->AddressOfNameOrdinals);

			return (ULONG64)base + funcRva[ordinalRva[i]];
		}
	}

	return 0;
}

BOOLEAN MemCopyWP(PVOID dest, PVOID src, ULONG length) {
	PMDL mdl = IoAllocateMdl(dest, length, FALSE, FALSE, NULL);
	if (!mdl) {
		return FALSE;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

	PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, 0, HighPagePriority);
	if (!mapped) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	memcpy(mapped, src, length);

	MmUnmapLockedPages(mapped, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return TRUE;
}