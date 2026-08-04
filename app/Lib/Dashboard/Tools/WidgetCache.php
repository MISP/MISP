<?php

App::uses('RedisTool', 'Tools');
App::uses('Inflector', 'Utility');

/**
 * Generic per-widget Redis cache for dashboard v2 (DD-20, generalised
 * from the AttributeGeoMapWidget-specific cache of DD-19).
 *
 * A widget opts in purely declaratively, with optional public
 * properties — no caching code in its handler():
 *
 *   public $cache_duration = 3600;                  // TTL seconds; > 0 enables
 *   public $cache_path = 'misp:attribute_geo_map_cache'; // optional key prefix
 *   public $cache_scope = 'user';                   // optional; per-user key
 *
 * When `cache_duration` is a positive int, DashboardsController::
 * renderWidget() wraps the handler() call in WidgetCache::remember():
 * the whole handler() payload is cached under
 *   "<path>:<sha256 of the config>"
 * and handed back verbatim on a hit, so each distinct config caches
 * independently for `cache_duration` seconds. A miss (or any Redis
 * failure) runs the handler live and stores the result.
 *
 * Path. `cache_path` if declared; otherwise auto-derived from the class
 * name as `misp:<snake_case(name without "Widget")>_cache` (e.g.
 * AttributeGeoMapWidget -> misp:attribute_geo_map_cache).
 *
 * Hash. sha256 of the JSON-encoded config, with keys ksort-ed (so key
 * order is irrelevant) and the framework-managed NON_DATA_KEYS removed.
 * Those keys (alias — DD-18; refresh_delay — Phase 5 scheduler) live in
 * `config` but never reach the handler's output, so excluding them lets
 * several differently-aliased instances of one widget share a cache
 * entry instead of each recomputing.
 *
 * Scope (DD-21). By default the key is config-only, NOT per-user — so a
 * widget that opts in with just `cache_duration` is expected to be an
 * ACL-free aggregate (the AttributeGeoMapWidget posture, DD-11): the same
 * config must yield the same payload for every viewer. A widget whose
 * handler() output instead depends on the requesting user's role/ACL
 * (e.g. TrendingAttributesWidget branches on perm_site_admin / org_id)
 * MUST declare `public $cache_scope = 'user'`; the key then carries a
 * `u<id>:` segment so one viewer's payload is never served to another.
 * A user-scoped widget rendered without a usable user id is NOT cached
 * (remember() falls back to a live compute) — failing safe rather than
 * risking a cross-user leak.
 *
 * Scope `org` (AD-04, analyst track). For an ACL-scoped *aggregate* — the
 * same payload for every user in an org, since MISP's ACL atom is the
 * organisation — declare `public $cache_scope = 'org'`. The key then carries
 * an `o<org_id>:` segment so same-org users share one entry (one compute per
 * org per TTL) while different orgs stay isolated. Site admins see all events
 * with no ACL filter, so they share a single `sa:` no-ACL bucket distinct
 * from every org bucket. Like `user`, an org-scoped widget rendered without a
 * usable org bucket (no org_id and not a site admin) is NOT cached.
 *
 * NB: within the TTL even a manual refresh serves the cached payload
 * (renderWidget can't distinguish a refresh from a page load) — the
 * accepted "simple, 1h" behaviour from DD-19.
 */
class WidgetCache
{
    /**
     * Config keys that are framework-managed presentation/scheduler
     * concerns rather than data inputs, and so are stripped before
     * hashing (they never change a widget's handler() output).
     */
    const NON_DATA_KEYS = array('alias', 'refresh_delay');

    /**
     * Run $compute, caching its result per (widget, config) when the
     * widget opts in (cache_duration > 0). Falls back to a live
     * $compute() on cache miss, opt-out, or any Redis failure.
     *
     * @param object   $widget  the loaded widget instance
     * @param array    $config  the (already canonical-translated) config
     * @param callable $compute () => mixed — the live render (handler call)
     * @param array    $user    the requesting user (only needed when the
     *                          widget declares cache_scope = 'user')
     * @return mixed
     */
    public static function remember($widget, array $config, callable $compute, $user = null)
    {
        $ttl = self::duration($widget);
        if ($ttl <= 0) {
            return $compute();
        }
        // A user-scoped widget must key by user (DD-21); an org-scoped widget
        // must key by org bucket (AD-04). Without a usable id/bucket we can't
        // isolate viewers, so skip caching rather than share an ACL-scoped
        // payload across the wrong audience.
        $scope = self::scope($widget);
        if ($scope === 'user' && empty($user['id'])) {
            return $compute();
        }
        if ($scope === 'org'
            && empty($user['org_id'])
            && empty($user['Role']['perm_site_admin'])) {
            return $compute();
        }
        $redis = self::redis();
        if ($redis === null) {
            return $compute();
        }
        $key = self::key($widget, $config, $user);
        try {
            $cached = RedisTool::deserialize($redis->get($key));
            if (is_array($cached)) {
                return $cached;
            }
        } catch (Exception $e) {
            // unreadable cache — fall through to a live compute
        }
        $data = $compute();
        try {
            $redis->setex($key, $ttl, RedisTool::serialize($data));
        } catch (Exception $e) {
            // best-effort: a write failure must not break the render
        }
        return $data;
    }

    /**
     * Whether the widget has opted into caching (cache_duration > 0).
     */
    public static function isCacheable($widget)
    {
        return self::duration($widget) > 0;
    }

    /**
     * The full Redis key: "<path>:<sha256 of the data-affecting config>",
     * or "<path>:u<id>:<sha256...>" for a user-scoped widget (DD-21).
     * NON_DATA_KEYS are stripped and the remaining keys ksort-ed before
     * hashing, so neither presentation keys nor key order affect it.
     */
    public static function key($widget, array $config, $user = null)
    {
        foreach (self::NON_DATA_KEYS as $k) {
            unset($config[$k]);
        }
        ksort($config);
        $prefix = self::path($widget) . ':';
        $scope = self::scope($widget);
        if ($scope === 'user' && !empty($user['id'])) {
            $prefix .= 'u' . (int)$user['id'] . ':';
        } elseif ($scope === 'org') {
            $prefix .= self::orgSegment($user);
        }
        return $prefix . hash('sha256', (string)json_encode($config));
    }

    /**
     * The key prefix: the declared `cache_path`, or an auto-derived
     * `misp:<snake_case(class without "Widget")>_cache`.
     */
    public static function path($widget)
    {
        if (isset($widget->cache_path) && is_string($widget->cache_path) && $widget->cache_path !== '') {
            return $widget->cache_path;
        }
        $class = preg_replace('/Widget$/', '', get_class($widget));
        return 'misp:' . Inflector::underscore($class) . '_cache';
    }

    /**
     * The opt-in TTL in seconds (0 = not cacheable).
     */
    private static function duration($widget)
    {
        return (isset($widget->cache_duration) && is_numeric($widget->cache_duration))
            ? (int)$widget->cache_duration
            : 0;
    }

    /**
     * The cache scope: 'user' (key carries a per-user segment) when the
     * widget declares cache_scope = 'user', otherwise 'global' (the
     * default config-only key).
     */
    private static function scope($widget)
    {
        if (isset($widget->cache_scope)
            && in_array($widget->cache_scope, array('user', 'org'), true)) {
            return $widget->cache_scope;
        }
        return 'global';
    }

    /**
     * The per-org key segment for an `org`-scoped widget (AD-04, analyst
     * track): MISP's ACL atom is the organisation, so same-org users share
     * one cache entry. Site admins see every event with NO ACL filter, so
     * they get a single shared no-ACL bucket (`sa:`) distinct from any org
     * bucket — their all-events payload must never be served to a
     * regular user and vice versa.
     */
    private static function orgSegment($user)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return 'sa:';
        }
        return 'o' . (int)$user['org_id'] . ':';
    }

    /**
     * Best-effort Redis handle (DB-13, prefix-free via RedisTool::init).
     * Returns null if Redis is unavailable so callers degrade to live.
     */
    private static function redis()
    {
        try {
            return RedisTool::init();
        } catch (Exception $e) {
            return null;
        }
    }
}
