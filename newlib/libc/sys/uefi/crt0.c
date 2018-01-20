#include <Base.h>
#include <PiDxe.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/Cpu.h>

#include <stdint.h>
#include <stdlib.h>
#include <elf.h>
#include <setjmp.h>

#if defined(__arm__)
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Word Elf_Word;
#define EFI_IMAGE_NT_HEADERS EFI_IMAGE_NT_HEADERS32
#define EFI_IMAGE_NT_OPTIONAL_HDR_MAGIC EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define Pe32Arch Pe32

#elif defined(__x86_64__)
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Word Elf_Word;
#define EFI_IMAGE_NT_HEADERS EFI_IMAGE_NT_HEADERS64
#define EFI_IMAGE_NT_OPTIONAL_HDR_MAGIC EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define Pe32Arch Pe32Plus
#else
    #error unsupported architecture
#endif

typedef struct {
    Elf_Word num_relocs;
    Elf_Addr got_address;
    Elf_Word got_size;

    Elf_Addr text_base;
    Elf_Word text_size;
} efi_relocation_hdr_t;

typedef struct {
    Elf_Addr address;
    Elf_Word type;
    Elf_Word sym_value;
} efi_relocation_t;

static EFI_GUID mEfiLoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID mEfiCpuArchProtocolGuid = EFI_CPU_ARCH_PROTOCOL_GUID;
static EFI_SYSTEM_TABLE *mST = NULL;
static EFI_BOOT_SERVICES *mBS = NULL;
static EFI_CPU_ARCH_PROTOCOL *mCpu = NULL;

EFI_HANDLE         gImageHandle;
EFI_SYSTEM_TABLE   *gST;
jmp_buf _exit_jmp_buf;
int _exit_return_value;
char **environ = (char **)0;

void __libc_init_array(void);
void __libc_fini_array(void);
void __libc_init_syscalls(void);
int main(int argc, char **argv);

static void efi_puts(const char *s) {
    uint8_t c16[4] = {0};

    while(*s) {
        if (*s == '\n') {
            c16[0] = '\r';
            mST->ConOut->OutputString(mST->ConOut, (CHAR16*)c16);
        }

        c16[0] = *s;
        mST->ConOut->OutputString(mST->ConOut, (CHAR16*)c16);
        s++;
    }
}

void __libc_efi_puts(const char *s) {
    return efi_puts(s);
}

static int do_relocate(efi_relocation_t *relocs, efi_relocation_hdr_t *reloc_hdr, intptr_t relocoffset) {
    uintptr_t i;
    uint32_t *got = (void*)(reloc_hdr->got_address + relocoffset);

    for(i=0; i<reloc_hdr->num_relocs; i++) {
        efi_relocation_t *rel = &relocs[i];
        void *loc = (void*)(rel->address + relocoffset);
        uint64_t *plocu64 = (uint64_t*)loc;
        uint32_t *plocu32 = (uint32_t*)loc;
        uint16_t *plocu16 = (uint16_t*)loc;
        int32_t offset;
        uint32_t tmp;
        uint32_t upper, lower;

        switch (rel->type) {
#if defined(__arm__)
            case R_ARM_TARGET1:
            case R_ARM_ABS32:
                *plocu32 += relocoffset;
                break;

            case R_ARM_THM_MOVW_ABS_NC:
            case R_ARM_THM_MOVT_ABS:
                upper = *plocu16;
                lower = *(plocu16 + 1);

                /*
                * MOVT/MOVW instructions encoding in Thumb-2:
                *
                * i     = upper[10]
                * imm4  = upper[3:0]
                * imm3  = lower[14:12]
                * imm8  = lower[7:0]
                *
                * imm16 = imm4:i:imm3:imm8
                */
                offset = relocoffset + rel->sym_value;

                if (rel->type == R_ARM_THM_MOVT_ABS)
                    offset >>= 16;

                upper = (uint16_t)((upper & 0xfbf0) |
                                  ((offset & 0xf000) >> 12) |
                                  ((offset & 0x0800) >> 1));
                lower = (uint16_t)((lower & 0x8f00) |
                                  ((offset & 0x0700) << 4) |
                                  (offset & 0x00ff));
                *plocu16 = upper;
                *(plocu16 + 2) = lower;
                break;

            case R_ARM_MOVW_ABS_NC:
            case R_ARM_MOVT_ABS:
                tmp = *plocu32;

                offset = relocoffset + rel->sym_value;
                if (rel->type == R_ARM_MOVT_ABS)
                    offset >>= 16;

                tmp &= 0xfff0f000;
                tmp |= ((offset & 0xf000) << 4) |
                        (offset & 0x0fff);

                *plocu32 = tmp;
                break;

#elif defined(__x86_64__)
            case R_X86_64_64:
                *plocu64 += relocoffset;
                break;
#else
            #error unsupported architecture
#endif

            default:
                efi_puts("invalid relocation type\n");
                return -1;
        }
    }

    for(i=0; i<reloc_hdr->got_size / sizeof(Elf_Addr); i++) {
        got[i] += relocoffset;
    }

    return 0;
}

EFI_STATUS
EFIAPI
_start (
  IN EFI_HANDLE        image_handle,
  IN EFI_SYSTEM_TABLE  *system_table
  )
{
    int rc;
    EFI_STATUS status;
    intptr_t relocoffset;
    EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
    EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  hdr;
    EFI_IMAGE_DOS_HEADER *dos_hdr;
    uintptr_t table_offset;
    EFI_IMAGE_SECTION_HEADER *sectionHeaders;
    efi_relocation_hdr_t *reloc_hdr;
    efi_relocation_t *relocs;

    mST = system_table;
    mBS = mST->BootServices;

    // get loaded image protocol
    status = mBS->HandleProtocol (image_handle, &mEfiLoadedImageProtocolGuid, (void**)&loaded_image);
    if (status) {
        efi_puts("Can't find LoadedImageProtocol\n");
        return EFI_LOAD_ERROR;
    }

    // get pe32 header
    dos_hdr = (EFI_IMAGE_DOS_HEADER *)loaded_image->ImageBase;
    if (dos_hdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
      hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)(loaded_image->ImageBase + (uintptr_t) ((dos_hdr->e_lfanew) & 0x0ffff));
    } else {
      hdr.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)loaded_image->ImageBase;
    }

    // get section headers
    table_offset = sizeof(EFI_IMAGE_DOS_HEADER) + 0x40 + sizeof (EFI_IMAGE_NT_HEADERS);
    sectionHeaders = (EFI_IMAGE_SECTION_HEADER*)(loaded_image->ImageBase + table_offset);

    // get esr
    reloc_hdr = (efi_relocation_hdr_t*)(loaded_image->ImageBase + sectionHeaders[2].PointerToRawData);
    relocs = (efi_relocation_t*)(((void*)reloc_hdr) + sizeof(efi_relocation_hdr_t));

    // get offset
    relocoffset = ((intptr_t)loaded_image->ImageBase + hdr.Pe32Arch->OptionalHeader.BaseOfCode) - reloc_hdr->text_base;

    // relocate
    if (relocoffset != 0) {
        status = mST->BootServices->LocateProtocol (&mEfiCpuArchProtocolGuid, NULL, (void **)&mCpu);
        if (status) {
            efi_puts("Can't find CpuArchProtocol\n");
            return EFI_LOAD_ERROR;
        }

        // unprotect text section
        status = mCpu->SetMemoryAttributes(mCpu, reloc_hdr->text_base + relocoffset, reloc_hdr->text_size, 0);
        if (status) {
            efi_puts("Can't make text section writable\n");
            return EFI_LOAD_ERROR;
        }

        rc = do_relocate(relocs, reloc_hdr, relocoffset);
        if (rc) {
            efi_puts("relocation error\n");
            return EFI_LOAD_ERROR;
        }

        // (re-)protect text section
        // Actually we don't have a way to check if we ever had RO-protection.
        // Either way, we probably want to enable that protection no matter what
        // UEFI decided to do.
        status = mCpu->SetMemoryAttributes(mCpu, reloc_hdr->text_base + relocoffset, reloc_hdr->text_size, EFI_MEMORY_RO);
        if (status) {
            efi_puts("Can't make text section RO\n");
            return EFI_LOAD_ERROR;
        }
    }

    gImageHandle = image_handle;
    gST = system_table;

    __libc_init_syscalls();

    if (setjmp(_exit_jmp_buf) == 0) {
        atexit(__libc_fini_array);
        __libc_init_array();

        exit(main(0, NULL));
        return EFI_ABORTED;
    }

    return _exit_return_value ? EFI_ABORTED : EFI_SUCCESS;
}
