<?php

/**
 * Pure-PHPUnit test for the generic dashboard WidgetCache helper (DD-20).
 * Follows the project convention (bare app/Test/*.php, no Cake bootstrap):
 * stub the framework classes the unit under test touches, then require it.
 *
 * Only the deterministic, Redis-free surface is unit-tested here —
 * isCacheable() (opt-in gating), path() (explicit vs auto-derived) and
 * key() (format, framework-key exclusion, order-independence). The
 * Redis-backed remember() round-trip is covered by live verification.
 */

if (!class_exists('App')) {
    class App
    {
        public static function uses($class = null, $package = null)
        {
            // no-op: WidgetCache's file-level App::uses() calls are inert
            // here; RedisTool is never reached by the methods under test.
        }
    }
}

if (!class_exists('Inflector')) {
    class Inflector
    {
        // Minimal CamelCase -> snake_case, matching Cake's underscore()
        // for the names exercised here.
        public static function underscore($string)
        {
            $string = preg_replace('/([a-z\d])([A-Z])/', '$1_$2', $string);
            $string = preg_replace('/([A-Z]+)([A-Z][a-z])/', '$1_$2', $string);
            return strtolower($string);
        }
    }
}

require_once __DIR__ . '/../Lib/Dashboard/Tools/WidgetCache.php';

// --- stub widgets ---------------------------------------------------------

// Opt-in, no explicit path (path auto-derived from the class name).
class WcGeoDemoWidget
{
    public $cache_duration = 3600;
}

// Opt-in with an explicit path.
class WcExplicitWidget
{
    public $cache_duration = 600;
    public $cache_path = 'misp:custom_geo_key';
}

// Not cacheable (declares nothing).
class WcPlainWidget
{
}

// Explicitly disabled (zero duration).
class WcZeroWidget
{
    public $cache_duration = 0;
}

// Non-numeric duration — treated as not cacheable.
class WcGarbageWidget
{
    public $cache_duration = 'soon';
}

use PHPUnit\Framework\TestCase;

class WidgetCacheTest extends TestCase
{
    public function testIsCacheableOptInGating()
    {
        $this->assertTrue(WidgetCache::isCacheable(new WcGeoDemoWidget()));
        $this->assertTrue(WidgetCache::isCacheable(new WcExplicitWidget()));
        $this->assertFalse(WidgetCache::isCacheable(new WcPlainWidget()));
        $this->assertFalse(WidgetCache::isCacheable(new WcZeroWidget()));
        $this->assertFalse(WidgetCache::isCacheable(new WcGarbageWidget()));
    }

    public function testExplicitPathWins()
    {
        $this->assertSame('misp:custom_geo_key', WidgetCache::path(new WcExplicitWidget()));
    }

    public function testDerivedPathStripsWidgetSuffixAndSnakeCases()
    {
        // WcGeoDemoWidget -> "WcGeoDemo" -> "wc_geo_demo" -> ...
        $this->assertSame('misp:wc_geo_demo_cache', WidgetCache::path(new WcGeoDemoWidget()));
    }

    public function testKeyFormatIsPathColonSha256()
    {
        $key = WidgetCache::key(new WcExplicitWidget(), ['time_window' => '30d']);
        $this->assertStringStartsWith('misp:custom_geo_key:', $key);
        $hash = substr($key, strlen('misp:custom_geo_key:'));
        $this->assertSame(64, strlen($hash));
        $this->assertRegExp('/^[0-9a-f]{64}$/', $hash);
    }

    public function testFrameworkKeysAreExcludedFromHash()
    {
        $w = new WcExplicitWidget();
        $base = WidgetCache::key($w, ['time_window' => '30d', 'sources' => ['ip']]);
        // alias + refresh_delay must NOT change the key — so several
        // differently-aliased instances of one widget share a cache entry.
        $withAlias = WidgetCache::key($w, [
            'time_window' => '30d',
            'sources' => ['ip'],
            'alias' => 'EU view',
            'refresh_delay' => 120,
        ]);
        $this->assertSame($base, $withAlias);
    }

    public function testKeyIsOrderIndependent()
    {
        $w = new WcExplicitWidget();
        $a = WidgetCache::key($w, ['time_window' => '30d', 'limit' => 10000]);
        $b = WidgetCache::key($w, ['limit' => 10000, 'time_window' => '30d']);
        $this->assertSame($a, $b);
    }

    public function testDataChangeChangesKey()
    {
        $w = new WcExplicitWidget();
        $a = WidgetCache::key($w, ['time_window' => '30d']);
        $b = WidgetCache::key($w, ['time_window' => '7d']);
        $this->assertNotSame($a, $b);
    }

    public function testDifferentWidgetsDoNotCollideOnSameConfig()
    {
        $a = WidgetCache::key(new WcExplicitWidget(), ['time_window' => '30d']);
        $b = WidgetCache::key(new WcGeoDemoWidget(), ['time_window' => '30d']);
        // Same config, different path prefix -> different key.
        $this->assertNotSame($a, $b);
    }

    public function testRememberPassesThroughWhenNotCacheable()
    {
        $called = 0;
        $out = WidgetCache::remember(new WcPlainWidget(), ['x' => 1], function () use (&$called) {
            $called++;
            return ['data' => 'live'];
        });
        $this->assertSame(['data' => 'live'], $out);
        $this->assertSame(1, $called, 'compute must run exactly once for an uncacheable widget');
    }
}
