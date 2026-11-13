/* Included by the file hooks and their native tests. Windows x64 only. */
enum { GUARD_PATH_CHARS = 2048 };

typedef struct {
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    WCHAR buffer[GUARD_PATH_CHARS];
} ObjectNameSnapshot;

/* Base and Ex rename/link classes have the same x64 layout. Keep the first
   four bytes intact for both ReplaceIfExists and the extended flags. */
typedef struct {
    ULONG flags;
    HANDLE root;
    ULONG name_bytes;
    WCHAR name[GUARD_PATH_CHARS];
} FileTargetSnapshot;
C_ASSERT(FIELD_OFFSET(FileTargetSnapshot, name) == 20);

/* Caller-owned storage may disappear during capture. Keep the fault handler
   around the copy only and validate the private bytes before using them. */
static __declspec(noinline) int copy_file_input(void *dest, const void *source, SIZE_T bytes) {
    __try {
        CopyMemory(dest, source, bytes);
        return 1;
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
                GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ?
                EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return 0;
    }
}

static int capture_object_name(ObjectNameSnapshot *snapshot, const OBJECT_ATTRIBUTES *input) {
    OBJECT_ATTRIBUTES *attrs = &snapshot->attributes;
    UNICODE_STRING *name = &snapshot->name;
    if (!input || !copy_file_input(attrs, input, sizeof(*attrs)) || attrs->Length != sizeof(*attrs))
        return 0;
    if (!attrs->ObjectName) return 1;
    if (!copy_file_input(name, attrs->ObjectName, sizeof(*name))) return 0;
    /* Input names are counted by Length. Windows pipe creation passes a
       nonempty name with MaximumLength zero. Bound the actual copy instead. */
    if (name->Length % sizeof(WCHAR) || name->Length >= sizeof(snapshot->buffer)) return 0;

    if (name->Length && (!name->Buffer || !copy_file_input(snapshot->buffer, name->Buffer, name->Length)))
        return 0;
    snapshot->buffer[name->Length / sizeof(WCHAR)] = 0;
    if (name->Buffer) name->Buffer = snapshot->buffer;
    name->MaximumLength = name->Buffer ? name->Length + sizeof(WCHAR) : 0;
    attrs->ObjectName = name;
    return 1;
}

static int capture_file_target(FileTargetSnapshot *target, const void *input, ULONG size, ULONG *captured) {
    const ULONG header = FIELD_OFFSET(FileTargetSnapshot, name);
    /* Ignore surplus caller padding, preserving the supplied size for short
       records. The length passed to the kernel must fit the local buffer. */
    *captured = size < sizeof(*target) ? size : sizeof(*target);
    if (!input || size < header || !copy_file_input(target, input, *captured)) return 0;
    return target->name_bytes <= *captured - header && target->name_bytes < sizeof(target->name) &&
           target->name_bytes % sizeof(WCHAR) == 0;
}
