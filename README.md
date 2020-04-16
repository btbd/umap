# umap

Windows UEFI bootkit that loads a generic driver manual mapper without using a UEFI runtime driver.

# Usage

1. Setup a FAT32 formatted flashdrive with the following filesystem structure: `\EFI\Boot\bootx64.efi` where `bootx64.efi` is the compiled bootkit.

2. Boot from the flashdrive.

3. Use the usermode program `umap` to manually map a driver. The driver must be designed to function without a real driver object. However, in place of the driver object parameter is a pointer to the pool allocated for the driver if needed.

    - For example: `umap test.sys`

# Compiling

The `mapper` and `umap` projects can both be compiled using standard Visual Studio (with WDK for `mapper`). Keep in mind that any changes to `mapper` must be updated in its corresponding bootkit resource. One could also just replace `mapper` with their own driver (make sure to have a nonce and undo the bootkit callback), which renders the usermode component irrelevant.

The bootkit by default expects an `edk2` directory in the repository's root with the EDK2 header and library files combined. You can use VisualUEFI for both of these, then simply combine the directories. Or, change the project layout to fit your UEFI development environment.

# Note

This PoC was only tested on Windows 10 1803, 1809, 1903, and 1909.