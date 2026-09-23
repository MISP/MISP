#!/usr/bin/env bash
# Run only disposable local images: no pull, published ports, or production DB.
set -euo pipefail
test_checkout=$(cd "$(dirname "$0")/../.." && pwd)
cake_source=$(cd "${1:?Usage: FastLookupIntegration.sh /path/to/cakephp/lib/Cake}" && pwd)
php_image=${MISP_PHP_IMAGE:-localhost/misp-live:tmp}
db_image=${MISP_MARIADB_IMAGE:-docker.io/library/mariadb:10.11}
redis_image=${MISP_REDIS_IMAGE:-docker.io/library/redis:7}
test_dir=$(mktemp -d /tmp/misp-fastlookup.XXXXXXXX)
db_container="misp-fastlookup-db-${test_dir##*.}"
redis_container="misp-fastlookup-redis-${test_dir##*.}"
php_container="misp-fastlookup-php-${test_dir##*.}"
cleanup() {
    podman rm --force "$php_container" "$redis_container" "$db_container" >/dev/null 2>&1 || true
    rm -rf "$test_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 755 "$test_dir"
mkdir "$test_dir/mysql" "$test_dir/redis"
chmod 777 "$test_dir/mysql" "$test_dir/redis"
podman run -d --pull=never --name "$db_container" --network=none \
    -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 --tmpfs /var/lib/mysql:rw,size=512m \
    -v "$test_dir/mysql:/run/mysqld" "$db_image" \
    --skip-networking --socket=/run/mysqld/mysql.sock >/dev/null
podman run -d --pull=never --name "$redis_container" --network=none \
    -v "$test_dir/redis:/socket" "$redis_image" \
    redis-server --port 0 --unixsocket /socket/redis.sock --unixsocketperm 777 \
    --save '' --appendonly no >/dev/null
ready=false
for attempt in {1..45}; do
    # Ignore the temporary server used during MariaDB initialization.
    if podman exec "$db_container" sh -c 'test "$(cat /proc/1/comm)" = mariadbd && mariadb-admin --socket=/run/mysqld/mysql.sock ping --silent' >/dev/null 2>&1 && \
        podman exec "$redis_container" redis-cli -s /socket/redis.sock ping >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
if [[ "$ready" != true ]]; then
    podman logs "$db_container"
    podman logs "$redis_container"
    exit 1
fi
podman run --rm --pull=never --name "$php_container" --network=none --entrypoint php \
    -v "$test_checkout:/work:ro" -v "$cake_source:/cake:ro" \
    -v "$test_dir/mysql:/mysql" -v "$test_dir/redis:/redis" -w /work "$php_image" \
    -d auto_prepend_file= -d memory_limit=512M \
    tests/benchmarks/FastLookupIntegration.php /cake /mysql/mysql.sock /redis/redis.sock
