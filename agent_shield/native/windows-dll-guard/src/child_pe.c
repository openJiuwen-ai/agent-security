/* Validate the child's 4096-byte image header before reading its import directory. */
#define CHILD_IMPORT_PATH_CAPACITY 1200
static DWORD child_import_limits(unsigned descriptors, unsigned path_bytes) {
    if (descriptors >= 128) return ERROR_TOO_MANY_MODULES;
    if (!path_bytes || path_bytes > CHILD_IMPORT_PATH_CAPACITY) return ERROR_INSUFFICIENT_BUFFER;
    return ERROR_SUCCESS;
}

static const IMAGE_NT_HEADERS64 *child_pe_header(const BYTE header[4096]) {
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)header;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 || dos->e_lfanew > 3000) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }
    const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(header + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH);
        return NULL;
    }
    return nt;
}
