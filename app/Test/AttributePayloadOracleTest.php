<?php
/**
 * Captures attribute and proposal payloads (pubsub, Kafka, workflow) for the
 * behaviour oracle (tests/value_oracle, suite "payloads"), which drives it.
 *
 * Skipped unless VALUE_ORACLE_PAYLOADS names a request file:
 * {"out": path, "attributes": {name: id}, "proposals": {name: id}}.
 * It boots the real application against the configured database, so it must
 * run on its own:
 *     ./app/Vendor/bin/phpunit app/Test/AttributePayloadOracleTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributePayloadOracleTest extends TestCase
{
    public function testCapture()
    {
        $requestFile = getenv('VALUE_ORACLE_PAYLOADS');
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
        require_once __DIR__ . '/AttributePayloadOracleSupport.php';

        $captured = AttributePayloadOracle::capture($request);
        $json = json_encode(
            $captured,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES |
            JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION |
            JSON_INVALID_UTF8_SUBSTITUTE
        );
        $this->assertNotFalse(file_put_contents($request['out'], $json));
        $this->assertSame(
            [],
            $this->valueIdKeys($captured),
            'value ids leaked into a payload'
        );
    }

    private function valueIdKeys($data, $path = '$')
    {
        $found = [];
        if (is_array($data)) {
            foreach ($data as $key => $value) {
                if ($key === 'value1_id' || $key === 'value2_id') {
                    $found[] = $path . '.' . $key;
                }
                $found = array_merge(
                    $found,
                    $this->valueIdKeys($value, $path . '.' . $key)
                );
            }
        }
        return $found;
    }
}
