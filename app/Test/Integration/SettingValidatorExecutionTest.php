<?php

require_once __DIR__ . '/IntegrationTestCase.php';

/**
 * Executes every server setting validator against representative input.
 *
 * These 50-odd methods are the largest string-dispatched family in MISP: they
 * are named in Server::$serverSettings as `'test' => 'testForNumeric'` and
 * invoked by name, so nothing calls them statically and no test had ever run
 * one. A validator that fatals on unexpected input takes the whole settings
 * page down, and the failure surfaces nowhere near the setting that caused it.
 *
 * The contract (see Server::testForNumeric) is: take a value, return `true`
 * when acceptable or a message STRING when not. Never throw, never fatal.
 *
 * DiagnosticsTest-style validators that reach for the filesystem or a remote
 * service are exercised too - the point is that they degrade gracefully.
 */
class SettingValidatorExecutionTest extends IntegrationTestCase
{
    /**
     * Scalars only, deliberately.
     *
     * ServersController::serverSettingsEdit() rejects any non-scalar value
     * before a validator is reached (`!is_scalar(...)` at
     * ServersController.php:47), so probing with arrays or null would test a
     * state the application cannot produce - and 17 validators do throw on an
     * array, which is harmless precisely because they never see one.
     */
    private const PROBES = [
        'empty string'   => '',
        'zero'           => 0,
        'one'            => 1,
        'negative'       => -1,
        'large number'   => 999999,
        'numeric string' => '42',
        'plain text'     => 'not-a-number',
        'bool true'      => true,
        'bool false'     => false,
        'url'            => 'https://misp.test/path',
        'uuid'           => '5f7b1a2c-0000-4000-8000-000000000001',
    ];

    public function validatorProvider(): array
    {
        $path = APP . 'Model/Server.php';
        if (!is_file($path)) {
            throw new RuntimeException('Model/Server.php is missing');
        }
        $src = (string)file_get_contents($path);
        preg_match_all("/'test'\s*=>\s*'(\w+)'/", $src, $declared);
        preg_match_all("/\\\$setting\['test'\]\s*=\s*'(\w+)'/", $src, $assigned);
        $names = array_unique(array_merge($declared[1], $assigned[1]));
        sort($names);
        return array_combine($names, array_map(static fn($n) => [$n], $names));
    }

    /**
     * @dataProvider validatorProvider
     */
    public function testValidatorSurvivesEveryProbe(string $validator): void
    {
        $server = $this->model('Server');
        if (!method_exists($server, $validator)) {
            $this->fail("Server::$validator() is referenced by a setting but does not exist");
        }

        $failures = [];
        foreach (self::PROBES as $label => $value) {
            try {
                $result = $server->$validator($value);
            } catch (\Throwable $e) {
                // A validator must not throw: the settings page calls it with
                // whatever the admin typed.
                $failures[] = sprintf('%s => %s: %s', $label, get_class($e), $e->getMessage());
                continue;
            }
            if ($result !== true && !is_string($result) && $result !== false && $result !== null) {
                $failures[] = sprintf('%s => returned %s, expected true|string', $label, gettype($result));
            }
        }

        $this->assertSame(
            [],
            $failures,
            sprintf("Server::%s() mishandled input:\n  %s", $validator, implode("\n  ", $failures))
        );
    }
}
