"""Windows proactor listener with a protected DACL on every pipe instance."""

import asyncio
from asyncio.windows_utils import BUFSIZE, PipeHandle

import _winapi

from .pipe_security import PIPE_REJECT_REMOTE_CLIENTS, PipeSecurity
from .errors import GuardPipeError


class GuardPipeServer:
    def __init__(self, name, protocol_factory):
        self.name = name
        self.protocol_factory = protocol_factory
        self.loop = asyncio.get_running_loop()
        self.pending = None
        self.listener = None
        self.security = None
        try:
            self.security = PipeSecurity()
            self._listen(first=True)
        except (OSError, AttributeError) as exc:
            self.close()
            raise GuardPipeError(f"Cannot create protected DLL Guard listener: {exc}") from exc

    def _listen(self, *, first=False):
        flags = _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED | 0x40000  # WRITE_DAC
        if first:
            flags |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE
        handle = _winapi.CreateNamedPipe(
            self.name,
            flags,
            _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
            _winapi.PIPE_UNLIMITED_INSTANCES,
            BUFSIZE,
            BUFSIZE,
            0,
            self.security.pointer().value,
        )
        self.listener = PipeHandle(handle)
        proactor = getattr(self.loop, "_proactor")
        self.pending = proactor.accept_pipe(self.listener)
        self.pending.add_done_callback(self._connected)

    def _connected(self, future):
        if self.security is None:
            if not future.cancelled():
                future.exception()
            return
        pipe, self.listener = self.listener, None
        self.pending = None
        try:
            try:
                future.result()
            except (BrokenPipeError, ConnectionResetError):
                return
            make_transport = getattr(self.loop, "_make_duplex_pipe_transport")
            make_transport(pipe, self.protocol_factory(), extra={"addr": self.name})
            pipe = None  # The transport owns the connected handle.
        finally:
            # Post the next listener before releasing our last handle to the name.
            try:
                self._listen()
            except OSError as exc:
                self.close()
                self.loop.call_exception_handler(
                    {
                        "message": "DLL Guard pipe listener stopped",
                        "exception": exc,
                    }
                )
            finally:
                if pipe is not None:
                    pipe.close()

    def allow_sid(self, sid):
        """Called only with an OS-read SID of a child already registered to this Job."""
        if sid in self.security.allowed_sids:
            return
        replacement = PipeSecurity(self.security.allowed_sids | {sid})
        try:
            if self.listener is None:
                raise GuardPipeError("No listener available while registering child identity")
            replacement.apply(self.listener.fileno())
        except BaseException:
            replacement.close()
            raise
        previous, self.security = self.security, replacement
        previous.close()

    def close(self):
        if self.pending is not None:
            self.pending.cancel()
            self.pending = None
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        if self.security is not None:
            self.security.close()
            self.security = None
