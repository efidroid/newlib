#include <Base.h>
#include <PiDxe.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/LoadedImage.h>

#include <stdint.h>
#include <stdlib.h>
#include <elf.h>
#include <setjmp.h>

typedef struct {
    Elf32_Word num_relocs;
    Elf32_Addr got_address;
} efi_relocation_hdr_t;

typedef struct {
    Elf32_Addr address;
    Elf32_Word type;
    Elf32_Word sym_value;
} efi_relocation_t;

static EFI_GUID mEfiLoadedImageProtocolGuid = { 0x5B1B31A1, 0x9562, 0x11D2, { 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B }};
static EFI_SYSTEM_TABLE *mST = NULL;
static EFI_BOOT_SERVICES *mBS = NULL;

EFI_HANDLE         gImageHandle;
EFI_SYSTEM_TABLE   *gST;
jmp_buf _exit_jmp_buf;
int _exit_return_value;

void __libc_init_array(void);
void __libc_fini_array(void);
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

static void ThumbMovtImmediatePatch (uint16_t *Instruction, uint16_t Address) {
    uint16_t  Patch;

    // First 16-bit chunk of instruciton
    Patch  = ((Address >> 12) & 0x000f);             // imm4 
    Patch |= (((Address & BIT11) != 0) ? BIT10 : 0); // i
    *Instruction = (*Instruction & ~0x040f) | Patch;

    // Second 16-bit chunk of instruction
    Patch  =  Address & 0x000000ff;          // imm8
    Patch |=  ((Address << 4) & 0x00007000); // imm3
    Instruction++;
    *Instruction = (*Instruction & ~0x70ff) | Patch;
}

static int do_relocate(efi_relocation_t *relocs, efi_relocation_hdr_t *reloc_hdr, intptr_t relocoffset) {
    uintptr_t i;
    void *got = (void*)(reloc_hdr->got_address + relocoffset);

    for(i=0; i<reloc_hdr->num_relocs; i++) {
        efi_relocation_t *rel = &relocs[i];
        uint32_t *ploc = (void*)(rel->address + relocoffset);

        switch (rel->type) {
            case R_ARM_TARGET1:
            case R_ARM_ABS32:
                *ploc += relocoffset;
                break;

            case R_ARM_THM_MOVW_ABS_NC:
            case R_ARM_THM_MOVT_ABS:
                if (rel->type==R_ARM_THM_MOVW_ABS_NC)
                    ThumbMovtImmediatePatch ((uint16_t *)ploc, relocoffset + rel->sym_value);
                else
                    ThumbMovtImmediatePatch ((uint16_t *)ploc, (relocoffset +rel->sym_value)>>16);
                break;

            case R_ARM_GOT32: {
                uint32_t *ploc_got = got + *ploc;
                *ploc_got += relocoffset;
                break;
            }

            default:
                efi_puts("invalid relocation type\n");
                return -1;
        }
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

    mST = system_table;
    mBS = mST->BootServices;

    // get loading offset
    __asm__(".Lphys_offset:\n\t"
            "ldr     r4, =.Lphys_offset\n\t"
            "adr     %0, .Lphys_offset\n\t"
            "sub     %0, %0, r4\n\t"
             :"=r"(relocoffset)
             :
             :"r4"
    );

    // get loaded image protocol
    status = mBS->HandleProtocol (image_handle, &mEfiLoadedImageProtocolGuid, (void**)&loaded_image);
    if (status) {
        return EFI_LOAD_ERROR;
    }

    // relocate
    if (relocoffset != 0) {
        intptr_t reloctbl_offset = (intptr_t)loaded_image->ImageBase + 0x1000;
        efi_relocation_hdr_t *reloc_hdr = (void*)(reloctbl_offset);
        efi_relocation_t * relocs = (void*)(reloctbl_offset + sizeof(efi_relocation_hdr_t));
        rc = do_relocate(relocs, reloc_hdr, relocoffset);
        if (rc) {
            return EFI_LOAD_ERROR;
        }
    }

    gImageHandle = image_handle;
    gST = system_table;

    atexit(__libc_fini_array);
    __libc_init_array();

    if (setjmp(_exit_jmp_buf) == 0) {
        exit(main(0, NULL));
        return EFI_ABORTED;
    }

    return _exit_return_value ? EFI_ABORTED : EFI_SUCCESS;
}
