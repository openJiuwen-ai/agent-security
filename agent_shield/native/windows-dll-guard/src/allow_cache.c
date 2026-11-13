/* Private to this process. The SDK signals the event before publishing a new
   policy; a signalled event is never reset or reused for another snapshot. */
static HANDLE cache_revoked;
static SRWLOCK cache_lock = SRWLOCK_INIT;
typedef struct {
    DWORD action;
    wchar_t resource[512];
} AllowEntry;
static AllowEntry allow_entries[256];

static AllowEntry *cache_slot(DWORD action, LPCWSTR resource) {
    if (!cache_revoked || (action != 1 && action != 33 && action != 34)) return NULL;
    if (action == 1 && ((wcsncmp(resource, L"\\??\\", 4) && wcsncmp(resource, L"\\\\?\\", 4)) ||
        !((resource[4] >= L'A' && resource[4] <= L'Z') ||
          (resource[4] >= L'a' && resource[4] <= L'z')) ||
        resource[5] != L':' || resource[6] != L'\\')) return NULL;
    if (WaitForSingleObject(cache_revoked, 0) != WAIT_TIMEOUT) return NULL;
    DWORD hash = action;
    for (size_t i = 0; resource[i]; i++) {
        if (i >= ARRAYSIZE(allow_entries[0].resource) - 1) return NULL;
        hash = hash * 31 + resource[i];
    }
    return &allow_entries[hash % ARRAYSIZE(allow_entries)];
}

static int cache_matches(AllowEntry *slot, DWORD action, LPCWSTR resource) {
    AcquireSRWLockShared(&cache_lock);
    int hit = slot->action == action && !wcscmp(slot->resource, resource);
    ReleaseSRWLockShared(&cache_lock);
    return hit;
}

static void cache_allow(AllowEntry *slot, DWORD action, LPCWSTR resource) {
    AcquireSRWLockExclusive(&cache_lock);
    wcscpy_s(slot->resource, ARRAYSIZE(slot->resource), resource);
    slot->action = action;
    ReleaseSRWLockExclusive(&cache_lock);
}
