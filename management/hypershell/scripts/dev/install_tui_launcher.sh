#!/bin/sh
# Install the normal-user TUI launcher (demo, scheme A).
#
# Creates:
#   /usr/local/bin/hypershell-tui       unprivileged entry point (runs sudo -n)
#   /usr/local/bin/hypershell-tui-root  root side that runs the Python launcher
#   /etc/sudoers.d/hypershell-tui       NOPASSWD whitelist for the root side
#
# The root side never forwards arbitrary arguments, so callers cannot point it
# at a different config or inject options. Authentication happens inside the
# root launcher against /etc/hypershell-demo/accounts.yaml (Argon2id).
#
# Run as root on the demo VM:  sudo sh scripts/dev/install_tui_launcher.sh
set -eu

PYTHON="${HYPERSHELL_WEB_PYTHON:-/opt/hypershell-control/bin/python}"
PYTHONPATH_DIR="${HYPERSHELL_ROOT:-/opt/hypershell-demo}"

# These paths are embedded into a privileged shell wrapper. Accept only simple
# absolute paths, then quote them in the generated command.
for path in "$PYTHON" "$PYTHONPATH_DIR"; do
    case "$path" in
        /*) ;;
        *) echo "expected an absolute administrator-controlled path" >&2; exit 1 ;;
    esac
    case "$path" in
        *[!a-zA-Z0-9_./-]*) echo "unsupported character in installation path" >&2; exit 1 ;;
    esac
done

if [ ! -x "$PYTHON" ]; then
    echo "python not found: $PYTHON" >&2
    exit 1
fi

cat > /usr/local/bin/hypershell-tui-root <<EOF
#!/bin/sh
exec env -i PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH='${PYTHONPATH_DIR}' '${PYTHON}' -P -B -m hypershell.tui_launcher
EOF

cat > /usr/local/bin/hypershell-tui <<'EOF'
#!/bin/sh
exec sudo -n /usr/local/bin/hypershell-tui-root
EOF

chmod 0755 /usr/local/bin/hypershell-tui-root /usr/local/bin/hypershell-tui

cat > /etc/sudoers.d/hypershell-tui <<'EOF'
# Allow local users to invoke only the fixed root TUI launcher (no shell).
ALL ALL=(root) NOPASSWD: /usr/local/bin/hypershell-tui-root
EOF
chmod 0440 /etc/sudoers.d/hypershell-tui

if command -v visudo >/dev/null 2>&1; then
    visudo -cf /etc/sudoers.d/hypershell-tui
fi

echo "installed: /usr/local/bin/hypershell-tui -> hypershell-tui-root"
echo "users may run: hypershell-tui"
