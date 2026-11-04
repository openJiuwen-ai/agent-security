"""The object ids and kinds the store holds.

There are two processes that talk to the store: the management backend and
the litellm plugin. Both must agree on how an object is named and what kind
it is, so the rule is written once here and both borrow it. Two copies of
this rule is two copies that will drift, and the symptom of drift is "the
secret comes back empty" or "the wrong secret goes out" — neither of which
points at the real cause.

A litellm secret name *is* the store's object id. There is no mapping:
a mapping table is one more thing to keep in sync, and it is one more
thing that can be wrong.
"""

from __future__ import annotations

#: The id of the master key in the store.
MASTER_KEY_ID = "LITELLM_MASTER_KEY"

#: Our namespace. The litellm plugin only answers for names under this
#: prefix (plus the master key): litellm asks about a pile of its own
#: switches on every request (``USE_LITELLM_PROXY``, ``DATABASE_URL`` and
#: so on), and those names are not in our store. Rather than asking the
#: store about each one and waiting for it to say "no", the plugin does not
#: ask at all.
NAMESPACE_PREFIX = "litellm/"
MODEL_KEY_PREFIX = NAMESPACE_PREFIX + "model/"
VKEY_PREFIX = NAMESPACE_PREFIX + "vkey/"

#: The kinds an object may have. Both processes share these.
KIND_MASTER_KEY = "litellm.master_key"
KIND_MODEL_KEY = "litellm.model_key"
KIND_VKEY = "litellm.vkey"
KIND_SECRET = "litellm.secret"


def model_key_id(model_name: str) -> str:
    """The id of a model's upstream api key in the store."""
    return f"{MODEL_KEY_PREFIX}{model_name}"


def vkey_id(uid: str, key_alias: str) -> str:
    """The id of a virtual key in the store."""
    return f"{VKEY_PREFIX}{uid}/{key_alias}"
