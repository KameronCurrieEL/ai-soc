#!/usr/bin/env bash
# Bring up the single-node Wazuh 4.9.2 lab. Safe to re-run (idempotent).
set -euo pipefail

WAZUH_VERSION="v4.9.2"
PROJECT="ai-soc-wazuh"   # distinct compose project: never touches old stacks/volumes
HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="$HERE/wazuh-docker/single-node"

# 1. Official compose files, pinned to a tag (not committed to our repo).
if [ ! -d "$HERE/wazuh-docker" ]; then
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$WAZUH_VERSION" \
    https://github.com/wazuh/wazuh-docker.git "$HERE/wazuh-docker"
fi

# 2. OpenSearch (the indexer) refuses to start below this kernel limit.
if [ "$(cat /proc/sys/vm/max_map_count)" -lt 262144 ]; then
  echo "vm.max_map_count too low. Run: sudo sysctl -w vm.max_map_count=262144" >&2
  exit 1
fi

# 3. TLS certs MUST exist before 'up', or Docker creates empty directories at
#    the bind-mount paths and the containers fail ("not a directory").
#    The certs dir becomes root-only (0500), so we can't look inside it;
#    a marker file records that generation finished.
cd "$DIR"
if [ ! -f config/.certs_generated ]; then
  docker compose -f generate-indexer-certs.yml run --rm generator
  touch config/.certs_generated
fi

# 4. Start (or keep running) the stack.
docker compose -p "$PROJECT" up -d
docker compose -p "$PROJECT" ps --format '{{.Name}}\t{{.Status}}'
echo "Dashboard: https://localhost  |  API check: make wazuh-check (wait ~1 min after first start)"
