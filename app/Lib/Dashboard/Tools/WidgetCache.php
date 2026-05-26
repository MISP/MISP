<?php

App::uses('RedisTool', 'Tools');
App::uses('Inflector', 'Utility');

/**
 * Generic per-widget Redis cache for dashboard v2 (DD-20, generalised
 * from the AttributeGeoMapWidget-specific cache of DD-19).
 *
 * A widget opts in purely declaratively, with two optional public
 * properties — no caching code in its handler():
 *
 *   public $cache_duration = 3600;                  // TTL seconds; > 0 enables
 *   public $cache_path = 'misp:attribute_geo_map_cache'; // optional key prefix
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
 * No-ACL assumption. The key is config-only, NOT per-user. A widget
 * that opts into this cache is therefore expected to be an ACL-free
 * aggregate (the AttributeGeoMapWidget posture, DD-11): the same config
 * must yield the same payload for every viewer. A future ACL-enforced
 * widget that wants caching would need a user/ACL-scope dimension in
 * the key and must not reuse this helper as-is.
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
     * @return mixed
     */
    public static function remember($widget, array $config, callable $compute)
    {
        $ttl = self::duration($widget);
        if ($ttl <= 0) {
            return $compute();
        }
        $redis = self::redis();
        if ($redis === null) {
            return $compute();
        }
        $key = self::key($widget, $config);
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
     * The full Redis key: "<path>:<sha256 of the data-affecting config>".
     * NON_DATA_KEYS are stripped and the remaining keys ksort-ed before
     * hashing, so neither presentation keys nor key order affect it.
     */
    public static function key($widget, array $config)
    {
        foreach (self::NON_DATA_KEYS as $k) {
            unset($config[$k]);
        }
        ksort($config);
        return self::path($widget) . ':' . hash('sha256', (string)json_encode($config));
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
