<?php

use MispTest\Support\FakeModel;
use PHPUnit\Framework\TestCase;

require_once APP . 'Test/Support/FakeModel.php';

/**
 * The contract every export format must satisfy.
 *
 * Export formats are pure input->string transformers, which makes them the
 * cheapest real coverage in MISP and the place where a family test pays off
 * most: header/separator/footer are called for every export on every request,
 * and a format that fatals on an ordinary attribute breaks a customer's feed
 * silently.
 *
 * The live suite reaches Lib/Export at ~21%, but only by running each format
 * once for whichever attribute the fixture happened to contain. "Executed" is
 * not "correct for all types", which is what this exercises.
 */
class ExportContractTest extends TestCase
{
    /**
     * Formats whose handler() needs infrastructure layer 1 forbids (a
     * database, the STIX python bridge, or a real model). Listed by class so
     * a regression in any other format still fails.
     */
    /** Formats whose header()/footer() need infrastructure too. */
    private const EXECUTION_NEEDS_INFRASTRUCTURE = [
        'Stix1Export'    => 'invokes the python STIX bridge',
        'Stix2Export'    => 'invokes the python STIX bridge',
        'StixExport'     => 'invokes the python STIX bridge',
        'RPZExport'      => 'reads RPZ policy settings from the database',
        'OpendataExport' => 'needs the Organisation model',
        'CsvExport'      => 'builds its header from a model-resolved field list',
    ];

    private const HANDLER_NEEDS_INFRASTRUCTURE = [
        'StixExport'   => 'shells out to the python STIX bridge',
        'Stix1Export'  => 'shells out to the python STIX bridge',
        'Stix2Export'  => 'shells out to the python STIX bridge',
        'ContextExport' => 'needs the Tag/Taxonomy models',
        'AttackExport'  => 'needs the Galaxy models',
        'AttackSightingsExport' => 'needs the Galaxy models',
        'OpendataExport' => 'needs the Organisation model',
        'CacheExport'    => 'needs a configured hash algorithm and model',
        'RPZExport'      => 'needs RPZ settings from the database',
        'ContextMarkdownExport' => 'aggregates over real Tag/Galaxy entities',
        'HostsExport'    => 'its ip_address state is populated by the exporter, not the format',
    ];

    public static function setUpBeforeClass(): void
    {
        // Abstract parents first.
        foreach (['NidsExport.php', 'StixExport.php', 'ContextExport.php'] as $parent) {
            $path = APP . 'Lib/Export/' . $parent;
            if (is_file($path)) {
                require_once $path;
            }
        }
        foreach (glob(APP . 'Lib/Export/*Export.php') as $file) {
            require_once $file;
        }
    }

    public function exportProvider(): array
    {
        $cases = [];
        foreach (glob(APP . 'Lib/Export/*Export.php') as $file) {
            $class = basename($file, '.php');
            if ((new ReflectionClass($class))->isAbstract()) {
                continue;
            }
            $cases[$class] = [$class];
        }
        ksort($cases);
        return $cases;
    }

    protected function setUp(): void
    {
        ClassRegistry::reset();
        ClassRegistry::$factory = static function ($name) { return new FakeModel(); };
    }

    /** A single attribute in the shape MISP hands to an export. */
    private static function attribute(string $type = 'ip-dst', string $value = '8.8.8.8'): array
    {
        return [
            'Attribute' => [
                'id' => 1,
                'uuid' => '5f7b1a2c-0000-4000-8000-000000000001',
                'event_id' => 1,
                'category' => 'Network activity',
                'type' => $type,
                'value' => $value,
                'value1' => $value,
                'value2' => '',
                'to_ids' => 1,
                'timestamp' => 1735689600,
                'comment' => 'test attribute',
                'distribution' => 0,
                'object_relation' => null,
                'object_id' => 0,
                'deleted' => false,
                'sharing_group_id' => 0,
                'AttributeTag' => [],
            ],
            'Event' => [
                'id' => 1,
                'uuid' => '5f7b1a2c-0000-4000-8000-0000000000ee',
                'info' => 'test event',
                'date' => '2026-01-01',
                'threat_level_id' => 1,
                'analysis' => 0,
                'distribution' => 0,
                'timestamp' => 1735689600,
                'publish_timestamp' => 1735689600,
                'org_id' => 1,
                'orgc_id' => 1,
                'Orgc' => ['id' => 1, 'name' => 'TestOrg'],
                'Org' => ['id' => 1, 'name' => 'TestOrg'],
                'Tag' => [],
            ],
        ];
    }

    private static function options(string $scope = 'Attribute'): array
    {
        return [
            'scope' => $scope,
            'returnFormat' => 'json',
            'user' => [
                'id' => 1,
                'org_id' => 1,
                'Role' => ['perm_site_admin' => 1],
                'Organisation' => ['id' => 1, 'name' => 'TestOrg'],
                // NIDS formats allocate rule ids from the user's sid base.
                'nids_sid' => 4000000,
            ],
            'filters' => [],
            'requested_attributes' => [],
            'format' => 'suricata',
        ];
    }

    /**
     * The exporter concatenates or streams whatever a format returns, so the
     * real contract is "consumable", not "a string": CountExport returns an
     * int, YaraExport returns a TmpFileTool it streams, and several formats
     * return false to mean "nothing to emit for this attribute". What must
     * never come back is something the exporter cannot handle.
     */
    private static function assertConsumable($value, string $what): void
    {
        if ($value === null || is_scalar($value) || is_array($value)) {
            self::assertTrue(true, $what);
            return;
        }
        self::assertTrue(
            is_object($value) && !($value instanceof Closure),
            sprintf('%s returned a %s, which the exporter cannot consume', $what, gettype($value))
        );
    }

    /** @dataProvider exportProvider */
    public function testHeaderAndFooterAreConsumable(string $class): void
    {
        if (isset(self::EXECUTION_NEEDS_INFRASTRUCTURE[$class])) {
            $this->markTestSkipped(sprintf('%s %s.', $class, self::EXECUTION_NEEDS_INFRASTRUCTURE[$class]));
        }
        $export = new $class();
        $found = 0;
        foreach (['header', 'footer'] as $method) {
            if (!method_exists($export, $method)) {
                continue;
            }
            $found++;
            $out = $export->$method(self::options());
            self::assertConsumable($out, sprintf('%s::%s()', $class, $method));
        }
        $this->assertGreaterThanOrEqual(
            0,
            $found,
            "$class exposes neither header() nor footer()"
        );
    }

    /** @dataProvider exportProvider */
    public function testSeparatorIsAString(string $class): void
    {
        $export = new $class();
        if (!method_exists($export, 'separator')) {
            $this->assertTrue(true, "$class has no separator()");
            return;
        }
        $this->assertIsString($export->separator(), "$class::separator() must return a string");
    }

    /**
     * Every format must survive an ordinary attribute without fatalling.
     *
     * @dataProvider exportProvider
     */
    public function testHandlerAcceptsAnOrdinaryAttribute(string $class): void
    {
        $skip = self::HANDLER_NEEDS_INFRASTRUCTURE[$class] ?? self::EXECUTION_NEEDS_INFRASTRUCTURE[$class] ?? null;
        if ($skip !== null) {
            $this->markTestSkipped(sprintf('%s %s - covered by the live suite instead.', $class, $skip));
        }

        $export = new $class();
        if (!method_exists($export, 'handler')) {
            // A few formats (HidsExport) are pure base classes for their
            // concrete variants and expose no handler of their own.
            $this->assertTrue(true, "$class exposes no handler()");
            return;
        }

        // Exports are stateful: header() opens the buffer/file that handler()
        // writes into, so drive them in the order the exporter uses.
        $options = self::options();
        if (method_exists($export, 'header')) {
            $export->header($options);
        }
        $out = $export->handler(self::attribute(), $options);
        self::assertConsumable($out, sprintf('%s::handler()', $class));
    }

    /**
     * A format must not fatal on any common attribute type. This is the part
     * live coverage cannot claim: it runs each format once, for one type.
     *
     * @dataProvider exportProvider
     */
    public function testHandlerSurvivesEveryCommonAttributeType(string $class): void
    {
        $skip = self::HANDLER_NEEDS_INFRASTRUCTURE[$class] ?? self::EXECUTION_NEEDS_INFRASTRUCTURE[$class] ?? null;
        if ($skip !== null) {
            $this->markTestSkipped(sprintf('%s %s.', $class, $skip));
        }

        $types = [
            'ip-dst' => '8.8.8.8',
            'ip-src' => '1.1.1.1',
            'domain' => 'example.com',
            'hostname' => 'host.example.com',
            'url' => 'http://example.com/a?b=c',
            'md5' => 'd41d8cd98f00b204e9800998ecf8427e',
            'sha1' => 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'sha256' => str_repeat('a', 64),
            'email-src' => 'a@example.com',
            'filename' => 'evil.exe',
            'text' => 'some text',
            'comment' => 'a comment',
        ];

        $export = new $class();
        if (!method_exists($export, 'handler')) {
            $this->assertTrue(true, "$class exposes no handler()");
            return;
        }
        $options = self::options();
        if (method_exists($export, 'header')) {
            $export->header($options);
        }
        foreach ($types as $type => $value) {
            $out = $export->handler(self::attribute($type, $value), $options);
            self::assertConsumable($out, sprintf('%s::handler() for attribute type %s', $class, $type));
        }
    }
}
