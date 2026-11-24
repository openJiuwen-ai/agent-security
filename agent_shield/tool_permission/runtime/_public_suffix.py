"""Offline public suffix lookup, imported only for URL approval scopes."""

from tld.utils import MozillaTLDSourceParser


class BundledSuffixList(MozillaTLDSourceParser):
    uid = None  # Private parser, never replace tld's registered default.

    @classmethod
    def update_tld_names(cls, fail_silently=False):
        # tld otherwise downloads a replacement when its packaged data is unreadable.
        raise OSError("Bundled public suffix list is unavailable")
