/* Own the destination bytes for both the policy decision and the Winsock call. */
static BOOL capture_socket_address(SOCKADDR_STORAGE *copy, const struct sockaddr **address, int length) {
    if (!*address) return TRUE; /* Connected sends use the socket's peer. */
    if (length < (int)sizeof(ADDRESS_FAMILY) || length > (int)sizeof(*copy)) {
        WSASetLastError(WSAEFAULT);
        return FALSE;
    }
    __try { memcpy(copy, *address, (size_t)length); }
    __except(EXCEPTION_EXECUTE_HANDLER) { WSASetLastError(WSAEFAULT); return FALSE; }
    *address = (const struct sockaddr *)copy;
    return TRUE;
}
