"""Public errors raised by the Windows DLL guard."""


class GuardError(RuntimeError):
    """Base class for guard-specific failures."""


class GuardPlatformError(GuardError):
    """The runtime cannot run on this platform."""


class GuardBundleError(GuardError):
    """The DLL or manifest could not be pinned or validated."""


class GuardBundleMissingError(FileNotFoundError, GuardBundleError):
    """A required bundle file was not found."""


class GuardStartupError(GuardError):
    """Failed to establish the guarded execution."""


class GuardPipeError(GuardStartupError):
    """Failed to create the authenticated local listener."""


class GuardInjectionError(GuardStartupError, OSError):
    """The root process failed guard setup before being returned to the caller."""


class GuardPolicyDenied(PermissionError, GuardError):
    """Policy denied startup of the requested program."""
