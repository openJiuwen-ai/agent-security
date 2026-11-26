# Examples

Run from the component directory after installing it from source.

| Entry | Purpose | Requirements / effects |
| --- | --- | --- |
| `demo/run_demo.py` | Allowed and denied policy previews | Python + PyYAML; only writes `demo-output/` |
| `demo/hypershell.yaml`, `demo/hypershell-roles.yaml` | Resource and role examples | Placeholder Linux paths; no real deployment |
| `demo/install_vm_demo.py` | Fixed-layout Linux lab bootstrap | Root; creates accounts, copies config and installs commands; review/adapt first |
| `demo/verify_vm_demo.py`, `demo/verify_native_file.py` | File boundary / native tool checks | Existing lab deployment; native tool check may call the model |
| `demo/verify_multiuser.py` | Concurrent workspaces and persistence | Existing lab; stops/recreates instances; chat enabled unless explicitly skipped |
| `demo/verify_roles.py` | Role limits and revocation after rebuild | Existing lab; stops/recreates instances and leaves synthetic verification data |

The installer still assumes a prepared application tree and lab data; it is not a
general installer for a new machine. Preserve backups and use disposable test workspaces.
For the VM verification scripts, use the dedicated control interpreter and explicitly
select the installed control package. From the administrator-controlled checkout,
run the required script with the same environment as in this example:

```bash
sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 PYTHONPATH=/opt/hypershell-demo \
  /opt/hypershell-control/bin/python -B examples/demo/verify_vm_demo.py
```

See the [user guide](../docs/USER_GUIDE.md) before running administrator tools.
