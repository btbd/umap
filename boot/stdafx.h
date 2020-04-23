#pragma once

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <IndustryStandard/PeImage.h>

#include "util.h"

#define MAPPER_BUFFER_SIZE (((IMAGE_NT_HEADERS64 *)(MAPPER_BUFFER + ((IMAGE_DOS_HEADER *)MAPPER_BUFFER)->e_lfanew))->OptionalHeader.SizeOfImage + sizeof(ALPCP_LIST_ENTRY))

typedef EFI_STATUS(EFIAPI *IMG_ARCH_START_BOOT_APPLICATION)(VOID *, VOID *, UINT32, UINT8, VOID *);
typedef EFI_STATUS(EFIAPI *BL_IMG_ALLOCATE_IMAGE_BUFFER)(VOID **, UINTN, UINT32, UINT32, VOID *, UINT32);
typedef EFI_STATUS(EFIAPI *OSL_FWP_KERNEL_SETUP_PHASE_1)(LOADER_PARAMETER_BLOCK *);
typedef VOID(*BLP_ARCH_SWITCH_CONTEXT)(BL_ARCH_MODE);

EFI_STATUS EFIAPI SetupHooks(EFI_HANDLE windows);
EFI_STATUS EFIAPI ImgArchStartBootApplicationHook(VOID *appEntry, VOID *imageBase, UINT32 imageSize, UINT8 bootOption, VOID *returnArguments);
EFI_STATUS EFIAPI BlImgAllocateImageBufferHook(VOID **imageBuffer, UINTN imageSize, UINT32 memoryType, UINT32 attributes, VOID *unused, UINT32 flags);
EFI_STATUS EFIAPI OslFwpKernelSetupPhase1Hook(LOADER_PARAMETER_BLOCK *loaderParameterBlock);
EFI_STATUS EFIAPI SetupMapper(KLDR_DATA_TABLE_ENTRY *ntoskrnl);
EFI_STATUS EFIAPI MapMapper(VOID *ntoskrnlBase, VOID **entryPoint, LIST_ENTRY *callbackList, BOOLEAN *callbacksEnabled);
EFI_STATUS EFIAPI ExitBootServicesHook(EFI_HANDLE imageHandle, UINTN mapKey);

EFI_DEVICE_PATH *EFIAPI GetWindowsDevicePath();