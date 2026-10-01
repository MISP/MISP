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

// User-scoped (DD-21): output depends on the requesting user's ACL, so
// the key must carry a per-user segment.
class WcUserScopedWidget
{
    public $cache_duration = 3600;
    public $cache_scope = 'user';
}

// Org-scoped (AD-04): output is an ACL-scoped aggregate shared by all users
// in an org, so the key carries a per-org segment (site admins → `sa:`).
class WcOrgScopedWidget
{
    public $cache_duration = 1200;
    public $cache_scope = 'org';
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
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
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

    // --- DD-21: per-user scope --------------------------------------------

    public function testUserScopeAddsUserSegmentToKey()
    {
        $w = new WcUserScopedWidget();
        $key = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7]);
        // misp:wc_user_scoped_cache:u7:<sha256>
        $this->assertStringStartsWith('misp:wc_user_scoped_cache:u7:', $key);
        $hash = substr($key, strlen('misp:wc_user_scoped_cache:u7:'));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    public function testUserScopeDifferentUsersGetDifferentKeys()
    {
        $w = new WcUserScopedWidget();
        $a = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7]);
        $b = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 8]);
        $this->assertNotSame($a, $b, 'same config, different user must not share a cache entry');
    }

    public function testUserScopeSameUserSameConfigSameKey()
    {
        $w = new WcUserScopedWidget();
        $a = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7]);
        $b = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7]);
        $this->assertSame($a, $b);
    }

    public function testGlobalScopeIgnoresUser()
    {
        // A global (default-scope) widget's key must not change when a
        // user is passed — config-only keying is preserved.
        $w = new WcExplicitWidget();
        $withUser = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7]);
        $withoutUser = WidgetCache::key($w, ['time_window' => '30d']);
        $this->assertSame($withoutUser, $withUser);
    }

    public function testRememberUserScopedWithoutUserRunsLive()
    {
        // No usable user id for a user-scoped widget -> fail safe: skip the
        // cache and compute live (never share an ACL-scoped payload).
        $called = 0;
        $out = WidgetCache::remember(new WcUserScopedWidget(), ['x' => 1], function () use (&$called) {
            $called++;
            return ['data' => 'live'];
        }, null);
        $this->assertSame(['data' => 'live'], $out);
        $this->assertSame(1, $called, 'compute must run live when a user-scoped widget lacks a user id');
    }

    // --- AD-04: per-org scope ---------------------------------------------

    public function testOrgScopeAddsOrgSegmentToKey()
    {
        $w = new WcOrgScopedWidget();
        $key = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7, 'org_id' => 5]);
        // misp:wc_org_scoped_cache:o5:<sha256>
        $this->assertStringStartsWith('misp:wc_org_scoped_cache:o5:', $key);
        $hash = substr($key, strlen('misp:wc_org_scoped_cache:o5:'));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $hash);
    }

    public function testOrgScopeSameOrgSharesKeyAcrossUsers()
    {
        // The point of per-org caching: two different users in the same org
        // share one cache entry (one compute per org per TTL).
        $w = new WcOrgScopedWidget();
        $a = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7, 'org_id' => 5]);
        $b = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 8, 'org_id' => 5]);
        $this->assertSame($a, $b);
    }

    public function testOrgScopeDifferentOrgsGetDifferentKeys()
    {
        $w = new WcOrgScopedWidget();
        $a = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7, 'org_id' => 5]);
        $b = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7, 'org_id' => 6]);
        $this->assertNotSame($a, $b, 'different orgs must not share an ACL-scoped cache entry');
    }

    public function testOrgScopeSiteAdminGetsSeparateNoAclBucket()
    {
        // Site admins see all events with no ACL filter, so their payload
        // goes to a single `sa:` bucket that no org user is ever served.
        $w = new WcOrgScopedWidget();
        $admin = WidgetCache::key($w, ['time_window' => '30d'],
            ['id' => 1, 'org_id' => 5, 'Role' => ['perm_site_admin' => 1]]);
        $this->assertStringStartsWith('misp:wc_org_scoped_cache:sa:', $admin);
        $orgUser = WidgetCache::key($w, ['time_window' => '30d'], ['id' => 7, 'org_id' => 5]);
        $this->assertNotSame($admin, $orgUser, 'site-admin no-ACL payload must not share an org key');
    }

    public function testRememberOrgScopedWithoutBucketRunsLive()
    {
        // No org_id and not a site admin -> can't isolate a bucket -> fail
        // safe: skip the cache and compute live.
        $called = 0;
        $out = WidgetCache::remember(new WcOrgScopedWidget(), ['x' => 1], function () use (&$called) {
            $called++;
            return ['data' => 'live'];
        }, ['id' => 7]);
        $this->assertSame(['data' => 'live'], $out);
        $this->assertSame(1, $called, 'compute must run live when an org-scoped widget lacks an org bucket');
    }
}
