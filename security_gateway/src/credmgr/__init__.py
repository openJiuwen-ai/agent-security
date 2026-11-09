"""The credential manager: the store, the keystore and the cache.

The packages that live under it are imported by their own names, not
through this one: ``security_gateway.credmgr.etcdstore`` for the etcd
backed record store, ``security_gateway.credmgr.store`` for the local
one, ``security_gateway.credmgr.clusterdek`` and
``security_gateway.credmgr.clusterkey`` for the cross-node key
hand-over.
"""

from __future__ import annotations
