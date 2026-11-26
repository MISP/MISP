<?php

use PHPUnit\Framework\TestCase;

if (!defined('APP')) {
    define('APP', __DIR__ . '/../');
}

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Export/StixExport.php';
require_once __DIR__ . '/../Lib/Export/Stix1Export.php';

class Stix1ExportTest extends TestCase
{
    /**
     * misp-stix validates the STIX 1 namespace as an absolute URI and refuses
     * to frame otherwise; MISP.baseurl ships empty and may be scheme-less.
     * Expected values follow misp-stix's own documented default.
     */
    public function testFramingNamespace(): void
    {
        $default = 'https://misp-project.org';
        $ext = 'https://ext.example';
        $cases = [
            // baseurl, external_baseurl, expected
            ['', '', $default],
            [null, null, $default],
            ['misp.local', '', $default],               // no scheme
            ['https://misp local', '', $default],       // space
            ['https://misp.local?a&b', '', $default],   // bare ampersand
            ["https://misp.local/'", '', $default],     // quote
            ['https://misp-project.org', '', $default],
            ['https://misp.local/', '', 'https://misp.local/'],
            ['http://localhost:8080', null, 'http://localhost:8080'],
            ['', $ext, $ext],
            ['misp.local', $ext, $ext],
            ['https://misp.local', $ext, 'https://misp.local'],
            ['', 'ext.example', $default],              // fallback validated
        ];
        foreach ($cases as [$baseurl, $externalBaseurl, $expected]) {
            $context = sprintf(
                'baseurl=%s external_baseurl=%s',
                var_export($baseurl, true),
                var_export($externalBaseurl, true)
            );
            $this->assertSame(
                $expected,
                Stix1Export::framingNamespace($baseurl, $externalBaseurl),
                $context
            );
        }
    }
}
