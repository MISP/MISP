#!/bin/sh

set -e

run_all_migrations() {
	./bin/cake migrations migrate
	./bin/cake migrations migrate -p tags
	./bin/cake migrations migrate -p ADmad/SocialAuth
}

delete_model_cache() {
	echo >&2 "Deleting cakephp cache..."
	rm -rf ./tmp/cache/models/*
	rm -rf ./tmp/cache/persistent/*
}

delete_model_cache

# waiting for DB to come up
for try in 1 2 3 4 5 6; do
	echo >&2 "migration - attempt $try"
	run_all_migrations && break || true
	sleep 5
	[ "$try" = "6" ] && exit 1
done

exec php-fpm -F "$@"
