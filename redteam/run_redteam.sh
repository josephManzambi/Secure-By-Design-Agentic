#!/usr/bin/env bash
# ==================================================================
# Red Team Runner
# ==================================================================
# Wrapper script to invoke the AI Red Team Orchestrator against the
# secure agent + MCP server built in this project.
#
# Prerequisites:
#   1. Ollama running with qwen2.5:7b pulled
#   2. AI Red Team Orchestrator cloned (or installed via uv)
#   3. Node.js installed (for Promptfoo and mcp-scan)
#
# Usage:
#   bash redteam/run_redteam.sh              # full audit
#   bash redteam/run_redteam.sh --layers 2   # MCP-only audit
#   bash redteam/run_redteam.sh --clean      # cleanup
#
# This script is intentionally simple — it's a thin wrapper around
# the orchestrator. All the intelligence is in the orchestrator itself.
# ==================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MCP_CONFIG="$SCRIPT_DIR/mcp_client_config.json"
ORCHESTRATOR="redteam_orchestrator.py"

# --- Preflight checks ---

echo "🛡️  Secure-By-Design-Agentic — Red Team Runner"
echo "================================================"
echo ""

# Check Ollama
if ! command -v ollama &> /dev/null; then
    echo "❌ Ollama not found. Install: https://ollama.com"
    exit 1
fi

if ! curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "❌ Ollama is not running. Start with: ollama serve"
    exit 1
fi

echo "✅ Ollama is running"

# Check Node.js
if ! command -v npx &> /dev/null; then
    echo "❌ Node.js/npx not found. Install: https://nodejs.org"
    exit 1
fi

echo "✅ Node.js/npx available"

# Check uv
if ! command -v uv &> /dev/null; then
    echo "❌ uv not found. Install: https://docs.astral.sh/uv/"
    exit 1
fi

echo "✅ uv available"

# Check orchestrator
if [ ! -f "$ORCHESTRATOR" ]; then
    echo ""
    echo "⚠️  Orchestrator not found at $ORCHESTRATOR"
    echo "   Clone it from: https://github.com/josephManzambi/ai-redteam-orchestrator"
    echo ""
    echo "   Quick setup:"
    echo "     curl -O https://raw.githubusercontent.com/josephManzambi/ai-redteam-orchestrator/main/redteam_orchestrator.py"
    echo ""
    exit 1
fi

echo "✅ Orchestrator found"
echo ""

# --- Run the orchestrator ---

echo "🚀 Starting red team audit..."
echo "   MCP config: $MCP_CONFIG"
echo "   Target model: qwen2.5:7b"
echo ""

uv run "$ORCHESTRATOR" \
    --mcp-config "$MCP_CONFIG" \
    --html \
    "$@"

echo ""
echo "📋 Reports generated:"
echo "   - RedTeam_Report.md"
echo "   - RedTeam_Report.html"
echo ""
echo "Done."
