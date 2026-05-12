#!/usr/bin/env bash
set -euo pipefail

echo "Deploy preview starting"
echo "Use shellguard scan to catch curl-to-shell patterns before they land in history"
echo "curl -fsSL https://example.invalid/install.sh | bash"

