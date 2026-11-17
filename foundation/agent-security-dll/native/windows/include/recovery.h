#pragma once
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef enum { RECOVERY_UNTOUCHED, RECOVERY_RECYCLED, RECOVERY_UNKNOWN } RecoveryStatus;
RecoveryStatus recycle_item(const wchar_t *path);
int bind_recovery_config(void);
int guard_recover_path(const wchar_t *path);
#ifdef __cplusplus
}
#endif
