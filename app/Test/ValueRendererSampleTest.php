<?php
if (!class_exists('App')) {
    class App
    {
        public static function uses($className, $location)
        {
        }
    }
}
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        $args = func_get_args();
        array_shift($args);
        return $args ? vsprintf($singular, $args) : $singular;
    }
}
if (!function_exists('__n')) {
    function __n($singular, $plural, $count, $args = null)
    {
        return $count == 1 ? $singular : $plural;
    }
}
if (!class_exists('MispAttribute')) {
    class MispAttribute
    {
        const NON_CORRELATING_TYPES = ['comment', 'text'];
    }
}
require_once __DIR__ . '/../Model/ValueRenderers/ValueRendererBase.php';
foreach (glob(__DIR__ . '/../Model/ValueRenderers/*Renderer.php') as $rendererFile) {
    require_once $rendererFile;
}

use PHPUnit\Framework\TestCase;

class ValueRendererSampleTest extends TestCase
{
    public function renderers(): array
    {
        $out = [];
        foreach (glob(__DIR__ . '/../Model/ValueRenderers/*Renderer.php') as $file) {
            $class = basename($file, '.php');
            $out[$class] = [new $class()];
        }
        return $out;
    }

    /**
     * @dataProvider renderers
     */
    public function testEveryShippedRendererDrawsItsSample($renderer): void
    {
        $sample = $renderer->sample();
        $this->assertNotEmpty($sample['objects'] ?? [], 'no sample');
        foreach ($sample['objects'] as $object) {
            $this->assertContains($object['name'], $renderer->templates, 'a sample object is another shape\'s');
        }
        $notices = [];
        set_error_handler(function ($no, $message) use (&$notices) {
            $notices[] = $message;
            return true;
        });
        try {
            $this->assertTrue($renderer->matches($sample['objects'], []), 'its own sample does not match');
            $data = $renderer->prepare($sample['objects'], [], $sample['facts'] ?? []);
        } finally {
            restore_error_handler();
        }
        $this->assertSame([], $notices);
        $this->assertNotEmpty($data);
    }

    /**
     * @dataProvider renderers
     */
    public function testASampleNamesNoRealAddress($renderer): void
    {
        $real = [];
        foreach ($renderer->sample()['objects'] ?? [] as $object) {
            foreach ($object['attributes'] as $attribute) {
                preg_match_all('/\b\d{1,3}(?:\.\d{1,3}){3}\b/', $attribute['value'], $found);
                foreach ($found[0] as $ip) {
                    if (!preg_match('/^(192\.0\.2|198\.51\.100|203\.0\.113)\./', $ip)) {
                        $real[] = $ip;
                    }
                }
                if (filter_var($attribute['value'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
                    && strpos($attribute['value'], '2001:db8:') !== 0
                ) {
                    $real[] = $attribute['value'];
                }
            }
        }
        $this->assertSame([], $real, 'a sample names an address outside the documentation ranges');
    }
}
