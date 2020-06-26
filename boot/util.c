#include "stdafx.h"

VOID MemCopy(VOID *dest, VOID *src, UINTN size) {
	for (UINT8 *d = dest, *s = src; size--; *d++ = *s++);
}

BOOLEAN CheckMask(CHAR8 *base, CHAR8 *pattern, CHAR16 *mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if (*mask == L'x' && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

VOID *FindPattern(CHAR8 *base, UINTN size, CHAR8 *pattern, CHAR16 *mask) {
	size -= StrLen(mask);
	for (UINTN i = 0; i <= size; ++i) {
		VOID *addr = &base[i];
		if (CheckMask(addr, pattern, mask)) {
			return addr;
		}
	}

	return NULL;
}

VOID *TrampolineHook(VOID *dest, VOID *src, UINT8 original[JMP_SIZE]) {
	if (original) {
		MemCopy(original, src, JMP_SIZE);
	}

	MemCopy(src, "\xFF\x25\x00\x00\x00\x00", 6);
	*(VOID **)((UINT8 *)src + 6) = dest;

	return src;
}

VOID TrampolineUnHook(VOID *src, UINT8 original[JMP_SIZE]) {
	MemCopy(src, original, JMP_SIZE);
}

KLDR_DATA_TABLE_ENTRY *GetModuleEntry(LIST_ENTRY *list, CHAR16 *name) {
	for (LIST_ENTRY *entry = list->ForwardLink; entry != list; entry = entry->ForwardLink) {
		KLDR_DATA_TABLE_ENTRY *module = CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (module && StrnCmp(name, module->BaseImageName.Buffer, module->BaseImageName.Length) == 0) {
			return module;
		}
	}

	return NULL;
}

UINT64 GetExport(UINT8 *base, CHAR8 *export) {
	IMAGE_DOS_HEADER *dosHeaders = (IMAGE_DOS_HEADER *)base;
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	IMAGE_NT_HEADERS64 *ntHeaders = (IMAGE_NT_HEADERS64 *)(base + dosHeaders->e_lfanew);

	UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportsRva) {
		return 0;
	}

	IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(base + exportsRva);
	UINT32 *nameRva = (UINT32 *)(base + exports->AddressOfNames);

	for (UINT32 i = 0; i < exports->NumberOfNames; ++i) {
		CHAR8 *func = (CHAR8 *)(base + nameRva[i]);
		if (func) {
			BOOLEAN equal = TRUE;
			for (CHAR8 *c = export; *c; ++func, ++c) {
				if (*func != *c) {
					equal = FALSE;
					break;
				}
			}

			equal &= !(*func);

			if (equal) {
				UINT32 *funcRva = (UINT32 *)(base + exports->AddressOfFunctions);
				UINT16 *ordinalRva = (UINT16 *)(base + exports->AddressOfNameOrdinals);

				return (UINT64)base + funcRva[ordinalRva[i]];
			}
		}
	}

	return 0;
}