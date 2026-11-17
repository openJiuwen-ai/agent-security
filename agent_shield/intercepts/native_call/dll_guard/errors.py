"""Public errors raised by the Windows DLL guard."""


class GuardError(RuntimeError):
    """Base class for guard-specific failures with a stable machine-readable code."""

    @property
    def code(self):
        return self.args[0] if self.args else "guard_error"


class GuardPlatformError(GuardError):
    """The runtime cannot run on this platform."""

    code = "unsupported_platform"


class GuardBundleError(GuardError):
    """The DLL or manifest could not be pinned or validated."""

    code = "invalid_bundle"


class GuardBundleMissingError(FileNotFoundError, GuardBundleError):
    """A required bundle file was not found."""

    code = "bundle_missing"


class GuardStartupError(GuardError):
    """Failed to establish the guarded execution."""

    code = "startup_failed"


class GuardPipeError(GuardStartupError):
    """Failed to create the authenticated local listener."""

    code = "ipc_failed"


class GuardInjectionError(GuardStartupError, OSError):
    """The root process failed guard setup before being returned to the caller."""

    code = "guard_setup_failed"


class GuardTargetArchitectureError(GuardInjectionError):
    """The installed runtime cannot protect this target architecture."""

    code = "unsupported_target_architecture"


class GuardPolicyDenied(PermissionError, GuardError):
    """Policy denied startup of the requested program."""

    code = "policy_denied"
