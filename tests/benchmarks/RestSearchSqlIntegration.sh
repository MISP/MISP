#!/usr/bin/env bash
# Requires local PHP (PDO MySQL) and MariaDB images; never pulls or exposes ports.
set -euo pipefail
test_checkout=$(cd "$(dirname "$0")/../.." && pwd)
cake_source=$(cd "${1:?Usage: RestSearchSqlIntegration.sh /path/to/cakephp/lib/Cake}" && pwd)
php_image=${MISP_PHP_IMAGE:-localhost/misp-live:tmp}
db_image=${MISP_MARIADB_IMAGE:-docker.io/library/mariadb:10.11}
test_dir=$(mktemp -d /tmp/misp-restsearch-sql.XXXXXXXX)
db_container="misp-restsearch-sql-${test_dir##*.}"
cleanup() {
    podman rm --force "$db_container" >/dev/null 2>&1 || true
    rm -rf "$test_dir"
}
trap cleanup EXIT
chmod 755 "$test_dir"
mkdir "$test_dir/socket"
chmod 777 "$test_dir/socket"
podman run -d --pull=never --name "$db_container" --network=none \
    -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 --tmpfs /var/lib/mysql:rw,size=256m \
    -v "$test_dir/socket:/run/mysqld" "$db_image" \
    --skip-networking --socket=/run/mysqld/mysql.sock >/dev/null
db_ready=false
for attempt in {1..30}; do
    # The entrypoint also starts a temporary initialization server. Wait until
    # it has exec'd the final server before accepting a successful socket ping.
    if podman exec "$db_container" sh -c 'test "$(cat /proc/1/comm)" = mariadbd && mariadb-admin --socket=/run/mysqld/mysql.sock ping --silent' >/dev/null 2>&1; then
        db_ready=true
        break
    fi
    sleep 1
done
if [[ "$db_ready" != true ]]; then
    podman logs "$db_container"
    exit 1
fi
podman run --rm --pull=never --network=none --entrypoint php \
    -v "$test_checkout:/work:ro" -v "$cake_source:/cake:ro" \
    -v "$test_dir/socket:/socket" -w /work "$php_image" \
    -d auto_prepend_file= tests/benchmarks/RestSearchSqlIntegration.php /cake /socket/mysql.sock
