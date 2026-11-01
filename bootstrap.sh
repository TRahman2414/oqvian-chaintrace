#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "\${BASH_SOURCE[0]}")/.." && pwd)"
(cd "$project_root/backend" && uv sync --extra dev)
(cd "$project_root/frontend" && npm ci)
printf '\\nDependencies installed. Run scripts/start-dev.sh to launch the local demo.\\n'
