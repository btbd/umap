#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <minwindef.h>
#include <ntstrsafe.h>

#include "util.h"

typedef struct _IMAGE_DATA {
	WORD Magic;
	ULONG Length;
	BYTE Buffer[1];
} IMAGE_DATA, *PIMAGE_DATA;

#define MAPPER_DATA_SIZE (JMP_SIZE + 7)

INT64 HalDispatchHook(PIMAGE_DATA imageData, PINT64 status);
NTSTATUS MapImage(PBYTE buffer, PCHAR error);