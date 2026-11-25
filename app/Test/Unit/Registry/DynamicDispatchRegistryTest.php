<?php

use PHPUnit\Framework\TestCase;

/**
 * Integrity of MISP's two string-dispatched registries.
 *
 * Two families of public methods are never called directly - they are named
 * as strings and dispatched at runtime:
 *
 *   - server setting validators, declared as `'test' => 'testForNumeric'`
 *     in Server::$serverSettings (and assigned dynamically in a few places);
 *   - restSearch filter handlers, declared as
 *     `'function' => 'set_filter_value'` in MispAttribute's filter map.
 *
 * Static analysis cannot see these call sites, so an IDE rename or a typo
 * leaves a setting that can never validate, or a filter that silently stops
 * being applied - with nothing failing at the point of the mistake. Together
 * they are 76 of the ~268 public methods on Event and Server.
 *
 * This test asserts the registries resolve. It reads the sources rather than
 * booting the models, so it belongs to layer 1 and needs no database.
 */
class DynamicDispatchRegistryTest extends TestCase
{
    private static function source(string $relative): string
    {
        $path = APP . $relative;
        // A missing path must fail loudly. Silently matching nothing would
        // turn this whole suite into a no-op that always passes.
        if (!is_file($path)) {
            throw new RuntimeException("expected source file is missing: $relative");
        }
        return (string)file_get_contents($path);
    }

    private static function publicMethods(string $relative): array
    {
        preg_match_all('/public function (\w+)\s*\(/', self::source($relative), $m);
        return array_flip($m[1]);
    }

    public function serverValidatorProvider(): array
    {
        $src = self::source('Model/Server.php');
        // Declared in the settings tree, plus the handful assigned at runtime.
        preg_match_all("/'test'\s*=>\s*'(\w+)'/", $src, $declared);
        preg_match_all("/\\\$setting\['test'\]\s*=\s*'(\w+)'/", $src, $assigned);
        $names = array_unique(array_merge($declared[1], $assigned[1]));
        sort($names);
        $this->assertNotEmpty($names);
        return array_combine($names, array_map(static fn($n) => [$n], $names));
    }

    /**
     * @dataProvider serverValidatorProvider
     */
    public function testEverySettingValidatorResolves(string $validator): void
    {
        $methods = self::publicMethods('Model/Server.php');
        $this->assertArrayHasKey(
            $validator,
            $methods,
            sprintf(
                "Server::\$serverSettings references the validator '%s', but no such public "
                . "method exists on Server. That setting can never be validated, and nothing "
                . "fails at the point the name was mistyped or renamed.",
                $validator
            )
        );
    }

    public function filterFunctionProvider(): array
    {
        $src = self::source('Model/MispAttribute.php');
        preg_match_all("/'function'\s*=>\s*'(\w+)'/", $src, $m);
        $names = array_unique($m[1]);
        sort($names);
        $this->assertNotEmpty($names, 'the restSearch filter map should not be empty');
        return array_combine($names, array_map(static fn($n) => [$n], $names));
    }

    /**
     * The filter map dispatches onto Event (via $this->Event) or onto
     * MispAttribute itself, so a handler may live in either.
     *
     * @dataProvider filterFunctionProvider
     */
    public function testEveryRestSearchFilterResolves(string $function): void
    {
        $candidates = array_merge(
            self::publicMethods('Model/Event.php'),
            self::publicMethods('Model/MispAttribute.php')
        );
        $this->assertArrayHasKey(
            $function,
            $candidates,
            sprintf(
                "The restSearch filter map references '%s', but no public method of that name "
                . "exists on Event or MispAttribute. That filter is silently ignored.",
                $function
            )
        );
    }

    /** Guards the guard: the parsers must actually be finding entries. */
    public function testRegistriesAreNonTrivial(): void
    {
        $this->assertGreaterThan(
            30,
            count($this->serverValidatorProvider()),
            'expected many distinct setting validators; the parser is probably not matching'
        );
        $this->assertGreaterThan(
            10,
            count($this->filterFunctionProvider()),
            'expected many restSearch filters; the parser is probably not matching'
        );
    }
}
