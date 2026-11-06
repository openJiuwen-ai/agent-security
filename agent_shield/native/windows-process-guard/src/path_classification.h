#ifndef AGENT_SECURITY_PATH_CLASSIFICATION_H
#define AGENT_SECURITY_PATH_CLASSIFICATION_H

#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Classify a Windows path before it is sent to Decide.
   Only the exact console/NUL devices are exempt. A \\.\ prefix is not. */

typedef enum PathClass {
    PATH_NORMAL = 0,
    PATH_PSEUDO_DEVICE,
    PATH_RAW_DISK,
    PATH_VOLUME,
    PATH_NAMED_PIPE,
    PATH_OTHER_DEVICE
} PathClass;

PathClass classify_path(const wchar_t* path);
int path_is_exempt(const wchar_t* path);
const char* path_device_class(PathClass kind);

#ifdef __cplusplus
}
#endif

#endif
