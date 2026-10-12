<?php
/**
 * Captures the statements and query plans of value-bearing operations for
 * the behaviour oracle (tests/value_oracle, suite "plans"), which drives it.
 *
 * Skipped unless VALUE_ORACLE_PLANS names a request file:
 * {"out": path, "operations": {name: {"op", "user", "args", "engine"}}}.
 * It boots the real application against the configured database, so it must
 * run on its own:
 *     ./app/Vendor/bin/phpunit app/Test/AttributePlanOracleTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributePlanOracleTest extends TestCase
{
    public function testCapture()
    {
        $requestFile = getenv('VALUE_ORACLE_PLANS');
        if (empty($requestFile)) {
            $this->markTestSkipped(
                'Behaviour oracle only, see tests/value_oracle.'
            );
        }
        if (class_exists('App', false)) {
            $this->markTestSkipped(
                'Needs its own process: run this file alone.'
            );
        }
        $request = json_decode(file_get_contents($requestFile), true);
        $this->assertIsArray($request);
        require_once __DIR__ . '/AttributePlanOracleSupport.php';

        $captured = AttributePlanOracle::capture($request);
        $json = json_encode(
            $captured,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES |
            JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
        );
        $this->assertNotFalse(file_put_contents($request['out'], $json));
    }
}
