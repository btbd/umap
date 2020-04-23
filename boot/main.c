#include "stdafx.h"
#include "mapper.h"

CHAR8 *gEfiCallerBaseName = "boot";
UINT32 _gUefiDriverRevision = 0;

EFI_EXIT_BOOT_SERVICES ExitBootServicesOriginal;

UINT8 ImgArchStartBootApplicationOriginal[JMP_SIZE];
IMG_ARCH_START_BOOT_APPLICATION ImgArchStartBootApplication;

UINT8 BlImgAllocateImageBufferOriginal[JMP_SIZE];
BL_IMG_ALLOCATE_IMAGE_BUFFER BlImgAllocateImageBuffer;

UINT8 OslFwpKernelSetupPhase1Original[JMP_SIZE];
OSL_FWP_KERNEL_SETUP_PHASE_1 OslFwpKernelSetupPhase1;

struct {
	VOID *Base;
	UINT32 Size;
	CHAR16 *ProtectedModeError;
	EFI_STATUS ProtectedModeStatus;
} winload = { NULL };

struct {
	VOID *AllocatedBuffer;
	EFI_STATUS AllocatedBufferStatus;
} mapper = { NULL };

// UEFI entrypoint
EFI_STATUS EFIAPI UefiMain(EFI_HANDLE imageHandle, EFI_SYSTEM_TABLE *systemTable) {
	gST->ConOut->ClearScreen(gST->ConOut);
	gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);

	// Locate the Windows EFI bootloader
	EFI_DEVICE_PATH *windowsPath = GetWindowsDevicePath();
	if (!windowsPath) {
		Print(L"Failed to find the Windows EFI bootloader\n");
		gBS->Stall(SEC_TO_MICRO(2));

		return EFI_NOT_FOUND;
	}

	// Load the Windows EFI bootloader
	EFI_HANDLE windows;
	EFI_STATUS status = gBS->LoadImage(TRUE, imageHandle, windowsPath, NULL, 0, &windows);
	if (EFI_ERROR(status)) {
		Print(L"Failed to load the Windows EFI boot loader: %r\n", status);
		gBS->Stall(SEC_TO_MICRO(2));

		gBS->FreePool(windowsPath);
		return status;
	}

	gBS->FreePool(windowsPath);

	// Setup the hook chain
	status = SetupHooks(windows);
	if (EFI_ERROR(status)) {
		Print(L"Failed to setup hooks: %r\n", status);
		gBS->Stall(SEC_TO_MICRO(2));

		gBS->UnloadImage(windows);
		return status;
	}

	// Start the Windows EFI bootloader
	status = gBS->StartImage(windows, NULL, NULL);
	if (EFI_ERROR(status)) {
		Print(L"Failed to start the Windows EFI boot loader: %r\n", status);
		gBS->Stall(SEC_TO_MICRO(2));

		gBS->UnloadImage(windows);
		return status;
	}

	return EFI_SUCCESS;
}

// Sets up the hook chain from bootmgr -> winload -> ntoskrnl
EFI_STATUS EFIAPI SetupHooks(EFI_HANDLE windows) {
	// Get the bootmgr image from the Windows bootloader handle
	EFI_LOADED_IMAGE *currentImage;
	EFI_STATUS status = gBS->HandleProtocol(windows, &gEfiLoadedImageProtocolGuid, (VOID **)&currentImage);
	if (EFI_ERROR(status)) {
		Print(L"Failed to get the boot manager image: %r\n", status);
		return status;
	}

	// Hook ImgArchStartBootApplication to setup winload hooks
	VOID *func = FindPattern(currentImage->ImageBase, currentImage->ImageSize, "\x48\x8B\xC4\x48\x89\x58\x20\x44\x89\x40\x18\x48\x89\x50\x10\x48\x89\x48\x08\x55\x56\x57\x41\x54", L"xxxxxxxxxxxxxxxxxxxxxxxx");
	if (!func) {
		Print(L"Failed to find ImgArchStartBootApplication\n");
		return EFI_NOT_FOUND;
	}

	ImgArchStartBootApplication = (IMG_ARCH_START_BOOT_APPLICATION)TrampolineHook((VOID *)ImgArchStartBootApplicationHook, func, ImgArchStartBootApplicationOriginal);

	return EFI_SUCCESS;
}

// Called from bootmgr to start the winload image
EFI_STATUS EFIAPI ImgArchStartBootApplicationHook(VOID *appEntry, VOID *imageBase, UINT32 imageSize, UINT8 bootOption, VOID *returnArguments) {
	TrampolineUnHook((VOID *)ImgArchStartBootApplication, ImgArchStartBootApplicationOriginal);

	winload.Base = imageBase;
	winload.Size = imageSize;

	// Find and hook OslFwpKernelSetupPhase1 to get a pointer to ntoskrnl 
	VOID *funcCall = FindPattern(imageBase, imageSize, "\x74\x07\xE8\x00\x00\x00\x00\x8B\xD8", L"xxx????xx");
	if (!funcCall) {
		Print(L"Failed to find OslExecuteTransition\n");
		gBS->Stall(SEC_TO_MICRO(2));
		
		return ImgArchStartBootApplication(appEntry, imageBase, imageSize, bootOption, returnArguments);
	}

	funcCall = FindPattern(RELATIVE_ADDR((UINT8 *)funcCall + 2, 5), 0x4F, "\x48\x8B\xCF\xE8", L"xxxx");
	if (!funcCall) {
		Print(L"Failed to find OslFwpKernelSetupPhase1\n");
		gBS->Stall(SEC_TO_MICRO(2));

		return ImgArchStartBootApplication(appEntry, imageBase, imageSize, bootOption, returnArguments);
	}

	OslFwpKernelSetupPhase1 = (OSL_FWP_KERNEL_SETUP_PHASE_1)TrampolineHook((VOID *)OslFwpKernelSetupPhase1Hook, RELATIVE_ADDR((UINT8 *)funcCall + 3, 5), OslFwpKernelSetupPhase1Original);

	// Hook BlImgAllocateImageBuffer to allocate the mapper's buffer
	funcCall = FindPattern(imageBase, imageSize, "\xE8\x00\x00\x00\x00\x4C\x8B\x6D\x60", L"x????xxxx");
	if (!funcCall) {
		Print(L"Failed to find BlImgAllocateImageBuffer\n");
		gBS->Stall(SEC_TO_MICRO(2));
		
		TrampolineUnHook((VOID *)OslFwpKernelSetupPhase1, OslFwpKernelSetupPhase1Original);
		return ImgArchStartBootApplication(appEntry, imageBase, imageSize, bootOption, returnArguments);
	}

	BlImgAllocateImageBuffer = (BL_IMG_ALLOCATE_IMAGE_BUFFER)TrampolineHook((VOID *)BlImgAllocateImageBufferHook, RELATIVE_ADDR(funcCall, 5), BlImgAllocateImageBufferOriginal);

	// Hook ExitBootServices
	ExitBootServicesOriginal = gBS->ExitBootServices;
	gBS->ExitBootServices = ExitBootServicesHook;

	return ImgArchStartBootApplication(appEntry, imageBase, imageSize, bootOption, returnArguments);
}

// Called by winload to allocate image buffers in protected mode, use it to allocate the mapper's buffer as well
// Hooking this instead of calling it within another hook alleviates some tedious setup (credits to sa413x)
EFI_STATUS EFIAPI BlImgAllocateImageBufferHook(VOID **imageBuffer, UINTN imageSize, UINT32 memoryType, UINT32 attributes, VOID *unused, UINT32 flags) {
	TrampolineUnHook((VOID *)BlImgAllocateImageBuffer, BlImgAllocateImageBufferOriginal);

	EFI_STATUS status = BlImgAllocateImageBuffer(imageBuffer, imageSize, memoryType, attributes, unused, flags);
	if (!EFI_ERROR(status) && memoryType == BL_MEMORY_TYPE_APPLICATION) {
		mapper.AllocatedBufferStatus = BlImgAllocateImageBuffer(&mapper.AllocatedBuffer, MAPPER_BUFFER_SIZE, memoryType, BL_MEMORY_ATTRIBUTE_RWX, unused, 0);
		if (EFI_ERROR(mapper.AllocatedBufferStatus)) {
			mapper.AllocatedBuffer = NULL;
		}

		// Don't hook the function again
		return status;
	}
	
	TrampolineHook((VOID *)BlImgAllocateImageBufferHook, (VOID *)BlImgAllocateImageBuffer, BlImgAllocateImageBufferOriginal);
	return status;
}

// Called by winload with a valid LPB in protected mode before calling ExitBootServices 
EFI_STATUS EFIAPI OslFwpKernelSetupPhase1Hook(LOADER_PARAMETER_BLOCK *loaderParameterBlock) {
	TrampolineUnHook((VOID *)OslFwpKernelSetupPhase1, OslFwpKernelSetupPhase1Original);

	if (mapper.AllocatedBuffer) {
		KLDR_DATA_TABLE_ENTRY *ntoskrnl = GetModuleEntry(&loaderParameterBlock->LoadOrderListHead, L"ntoskrnl.exe");
		if (ntoskrnl) {
			winload.ProtectedModeStatus = SetupMapper(ntoskrnl);
		} else {
			winload.ProtectedModeStatus = EFI_NOT_FOUND;
			winload.ProtectedModeError = L"Failed to find ntoskrnl module entry";
		}
	} else {
		winload.ProtectedModeStatus = mapper.AllocatedBufferStatus;
		winload.ProtectedModeError = L"Failed to allocate image memory";
	}

	return OslFwpKernelSetupPhase1(loaderParameterBlock);
}

// Sets up the mapper (in protected mode)
EFI_STATUS EFIAPI SetupMapper(KLDR_DATA_TABLE_ENTRY *ntoskrnl) {
	// Locate AlpcpLogCallbackListHead to insert a custom callback
	VOID *dataAccess = FindPattern(ntoskrnl->ImageBase, ntoskrnl->SizeOfImage, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xEB\x09", L"xxx????xxx????xx");
	if (!dataAccess) {
		winload.ProtectedModeError = L"Failed to find AlpcpLogCallbackListHead";
		return EFI_NOT_FOUND;
	}

	LIST_ENTRY *alpcpLogCallbackListHead = RELATIVE_ADDR(dataAccess, 7);

	// Locate AlpcpLogEnabled to enable ALPCP logging 
	dataAccess = FindPattern(ntoskrnl->ImageBase, ntoskrnl->SizeOfImage, "\x80\x3D\x00\x00\x00\x00\x00\x48\x8B\x84\x24\x00\x00\x00\x00\x48\x8B\x8C\x24", L"xx?????xxxx????xxxx");
	if (!dataAccess) {
		winload.ProtectedModeError = L"Failed to find AlpcpLogEnabled";
		return EFI_NOT_FOUND;
	}

	BOOLEAN *alpcpLogEnabled = ((BOOLEAN *)RELATIVE_ADDR(dataAccess, 6)) + 1;

	VOID *mapperEntryPoint;
	EFI_STATUS status = MapMapper(ntoskrnl->ImageBase, &mapperEntryPoint, alpcpLogCallbackListHead, alpcpLogEnabled);
	if (EFI_ERROR(status)) {
		return status;
	}

	// Setup the custom callback entry
	ALPCP_LIST_ENTRY *mapperListEntry = mapper.AllocatedBuffer;
	mapperListEntry->Callback = mapperEntryPoint;
	
	// Insert the custom callback
	InsertTailList(alpcpLogCallbackListHead, (LIST_ENTRY *)mapperListEntry);

	// Enable logging
	*alpcpLogEnabled = TRUE;

	return EFI_SUCCESS;
}

// Maps the driver manual mapper (in protected mode)
EFI_STATUS EFIAPI MapMapper(VOID *ntoskrnlBase, VOID **entryPoint, LIST_ENTRY *alpcpLogCallbackListHead, BOOLEAN *alpcpLogEnabled) {
	// The start of the mapper's allocated buffer is used for its ALPCP entry
	UINT8 *mapperBase = (UINT8 *)mapper.AllocatedBuffer + sizeof(ALPCP_LIST_ENTRY);
	UINT8 *mapperBuffer = MAPPER_BUFFER;
	
	// No point in checking signature when it's controlled
	IMAGE_NT_HEADERS64 *ntHeaders = (IMAGE_NT_HEADERS64 *)(mapperBuffer + ((IMAGE_DOS_HEADER *)mapperBuffer)->e_lfanew);

	// Map headers
	MemCopy(mapperBase, mapperBuffer, sizeof(ntHeaders->Signature) + sizeof(ntHeaders->FileHeader) + sizeof(ntHeaders->FileHeader.SizeOfOptionalHeader));

	// Map sections
	IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)((UINT8 *)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
	for (UINT16 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER *section = &sections[i];
		if (section->SizeOfRawData) {
			// Fill in mapper data
			UINT8 *mapperData = FindPattern(mapperBuffer + section->PointerToRawData, section->SizeOfRawData, "\x67\x89", L"xx");
			if (mapperData) {
				*(LIST_ENTRY **)&mapperData[sizeof(UINT16)] = alpcpLogCallbackListHead;
				*(BOOLEAN **)&mapperData[sizeof(UINT16) + sizeof(LIST_ENTRY *)] = alpcpLogEnabled;
			}

			MemCopy(mapperBase + section->VirtualAddress, mapperBuffer + section->PointerToRawData, section->SizeOfRawData);
		}
	}

	// Resolve ntoskrnl imports
	UINT32 importsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (importsRva) {
		IMAGE_IMPORT_DESCRIPTOR *importDescriptor = (IMAGE_IMPORT_DESCRIPTOR *)(mapperBase + importsRva);

		for (; importDescriptor->FirstThunk; ++importDescriptor) {
			IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64 *)(mapperBase + importDescriptor->FirstThunk);
			IMAGE_THUNK_DATA64 *thunkOriginal = (IMAGE_THUNK_DATA64 *)(mapperBase + importDescriptor->OriginalFirstThunk);

			for (; thunk->u1.AddressOfData; ++thunk, ++thunkOriginal) {
				UINT64 import = GetExport(ntoskrnlBase, ((IMAGE_IMPORT_BY_NAME *)(mapperBase + thunkOriginal->u1.AddressOfData))->Name);
				if (!import) {
					winload.ProtectedModeError = L"Failed to resolve all imports";
					return EFI_NOT_FOUND;
				}

				thunk->u1.Function = import;
			}
		}
	}

	// Resolve relocations
	IMAGE_DATA_DIRECTORY *baseRelocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (baseRelocDir->VirtualAddress) {
		IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)(mapperBase + baseRelocDir->VirtualAddress);

		for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size; ) {
			UINT32 relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);
			UINT16 *relocData = (UINT16 *)((UINT8 *)reloc + sizeof(IMAGE_BASE_RELOCATION));
			UINT8 *relocBase = mapperBase + reloc->VirtualAddress;

			for (UINT32 i = 0; i < relocCount; ++i) {
				UINT16 data = *relocData;
				UINT16 type = data >> 12;
				UINT16 offset = data & 0xFFF;

				if (type == IMAGE_REL_BASED_DIR64) {
					UINT64 *rva = (UINT64 *)(relocBase + offset);
					*rva = (UINT64)(mapperBase + (*rva - ntHeaders->OptionalHeader.ImageBase));
				} else {
					winload.ProtectedModeError = L"Unsupported relocation type";
					return EFI_UNSUPPORTED;
				}
			}

			currentSize += reloc->SizeOfBlock;
		}
	}

	*entryPoint = mapperBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
	return EFI_SUCCESS;
}

// Called by winload to unload boot services
EFI_STATUS EFIAPI ExitBootServicesHook(EFI_HANDLE imageHandle, UINTN mapKey) {
	if (EFI_ERROR(winload.ProtectedModeStatus)) {
		Print(L"%s: %r\n", winload.ProtectedModeError, winload.ProtectedModeStatus);
		gBS->Stall(SEC_TO_MICRO(2));
	} else {
		Print(L"Success\n");
	}

	gBS->ExitBootServices = ExitBootServicesOriginal;
	return gBS->ExitBootServices(imageHandle, mapKey);
}

// Locates the device path for the Windows bootloader
EFI_DEVICE_PATH *EFIAPI GetWindowsDevicePath() {
	STATIC CHAR16 *windowsPath = L"\\efi\\microsoft\\boot\\bootmgfw.efi";

	UINTN handleCount;
	EFI_HANDLE *handles;
	EFI_DEVICE_PATH *devicePath = NULL;

	// Retrieve filesystem handles
	EFI_STATUS status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &handleCount, &handles);
	if (EFI_ERROR(status)) {
		Print(L"Failed to get filesystem handles: %r\n", status);
		return devicePath;
	}

	// Check each FS for the bootloader
	for (UINTN i = 0; i < handleCount && !devicePath; ++i) {
		EFI_FILE_IO_INTERFACE *fileSystem;
		status = gBS->OpenProtocol(handles[i], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&fileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (EFI_ERROR(status)) {
			continue;
		}

		EFI_FILE_HANDLE volume;
		status = fileSystem->OpenVolume(fileSystem, &volume);
		if (!EFI_ERROR(status)) {
			EFI_FILE_HANDLE file;
			status = volume->Open(volume, &file, windowsPath, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
			if (!EFI_ERROR(status)) {
				volume->Close(file);

				devicePath = FileDevicePath(handles[i], windowsPath);
			}
		}

		gBS->CloseProtocol(handles[i], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL);
	}

	gBS->FreePool(handles);
	return devicePath;
}

EFI_STATUS EFIAPI UefiUnload(EFI_HANDLE imageHandle) {
	return EFI_SUCCESS;
}