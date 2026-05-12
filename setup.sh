#!/usr/bin/env bash
# Scrutics one-command setup
set -e
PYTHON=${PYTHON:-python3}
echo ""
echo "  Scrutics Setup"
echo "  =============="
echo ""
echo "[1/3] Checking Python..."
PY_OK=$($PYTHON -c "import sys; print('ok' if sys.version_info >= (3,10) else 'fail')")
PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if [ "$PY_OK" != "ok" ]; then
    echo "  [!] Python 3.10+ required. Found: $PY_VER"
    exit 1
fi
echo "  [ok] Python $PY_VER"

echo ""
echo "[2/3] Installing system dependencies..."
if command -v apt-get &>/dev/null; then
    sudo apt-get install -y libpcap-dev -q 2>/dev/null || true
fi
echo "  [ok] Done"

echo ""
echo "[3/3] Installing Python packages..."
$PYTHON -m pip install "scapy>=2.5.0" "textual>=0.80.0" "pyyaml>=6.0" \
    --quiet --break-system-packages --ignore-installed pygments 2>/dev/null || \
$PYTHON -m pip install "scapy>=2.5.0" "textual>=0.80.0" "pyyaml>=6.0" \
    --quiet --ignore-installed pygments
echo "  [ok] Done"

echo ""
echo "  Setup complete!"
echo ""
echo "  Run Scrutics:"
echo "    sudo $PYTHON -m scrutics              # Interactive TUI"
echo "    sudo $PYTHON -m scrutics --help       # CLI usage"
echo "    $PYTHON -m scrutics --file cap.pcap   # File analysis (no sudo needed)"
echo ""
