#!/bin/bash
# Setup script for SIFT-Eye on SIFT Workstation VM
# Run this inside the SIFT VM after boot
set -euo pipefail

echo "=== SIFT-Eye Setup on SIFT Workstation ==="

# 1. Install Node.js (for Claude Code)
echo "[1/5] Installing Node.js 20..."
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi
echo "  Node: $(node --version)"

# 2. Install Claude Code
echo "[2/5] Installing Claude Code..."
if ! command -v claude &>/dev/null; then
    sudo npm install -g @anthropic-ai/claude-code
fi
echo "  Claude Code: $(claude --version 2>/dev/null || echo 'installed')"

# 3. Install Protocol SIFT (if not already installed)
echo "[3/5] Checking Protocol SIFT..."
if ! command -v protocol-sift &>/dev/null; then
    echo "  Installing Protocol SIFT..."
    curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
else
    echo "  Protocol SIFT already installed"
fi

# 4. Clone and install sift-eye
echo "[4/5] Setting up SIFT-Eye..."
if [ ! -d "$HOME/sift-eye" ]; then
    git clone https://github.com/4KInc/sift-eye.git "$HOME/sift-eye"
fi
cd "$HOME/sift-eye/mcp-server"
pip3 install -e . 2>/dev/null || pip install -e .
echo "  SIFT-Eye MCP server installed"

# 5. Create evidence directory
echo "[5/5] Setting up evidence directory..."
sudo mkdir -p /evidence
sudo chmod 755 /evidence
echo "  Evidence directory: /evidence"

# Create case output directory
mkdir -p /tmp/sift-eye
echo "  Case output: /tmp/sift-eye"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Copy evidence files to /evidence/"
echo "     - rocba-cdrive.e01"
echo "     - Rocba-Memory.raw (unzip Rocba-Memory.zip first)"
echo ""
echo "  2. Start Claude Code:"
echo "     cd ~/sift-eye && claude"
echo ""
echo "  3. Tell the agent:"
echo '     "Investigate /evidence/rocba-cdrive.e01 and /evidence/Rocba-Memory.raw"'
