<?php
/**
 * RestResponseComponent::sandboxInlineFile() unit tests.
 *
 * Pure — no DB, no CakePHP bootstrap. The component is required with a
 * stubbed Component base and a recording CakeResponse stub, and the
 * subject method is reached with ReflectionClass::newInstanceWithoutConstructor()
 * because it depends on nothing in $this.
 *
 * The method is the single sink that keeps an inline-served SVG from
 * executing its own script on the MISP origin: when a file is served
 * with download = false and is an SVG, it attaches a sandboxing CSP and
 * X-Content-Type-Options: nosniff. Raster images and downloads must pass
 * through untouched, so a logo still renders through <img> and an
 * attachment download is unchanged.
 */

use PHPUnit\Framework\TestCase;

if (!class_exists('Component', false)) {
    class Component
    {
    }
}

if (!class_exists('CakeResponse', false)) {
    class CakeResponse
    {
        public $headers = [];

        public function header($header = null, $value = null)
        {
            $this->headers[$header] = $value;
            return $this->headers;
        }
    }
}

require_once __DIR__ . '/../Controller/Component/RestResponseComponent.php';

class RestResponseSandboxInlineFileTest extends TestCase
{
    /** @var RestResponseComponent */
    private $component;

    protected function setUp(): void
    {
        $this->component = (new ReflectionClass('RestResponseComponent'))
            ->newInstanceWithoutConstructor();
    }

    private function headersFor($type): array
    {
        $response = new CakeResponse();
        $this->component->sandboxInlineFile($response, $type);
        return $response->headers;
    }

    public function testSvgExtensionIsSandboxed(): void
    {
        $headers = $this->headersFor('svg');
        $this->assertArrayHasKey('Content-Security-Policy', $headers);
        $this->assertStringContainsString('sandbox', $headers['Content-Security-Policy']);
        $this->assertStringContainsString("default-src 'none'", $headers['Content-Security-Policy']);
        $this->assertSame('nosniff', $headers['X-Content-Type-Options']);
    }

    public function testSvgMimeTypeIsSandboxed(): void
    {
        $this->assertArrayHasKey('Content-Security-Policy', $this->headersFor('image/svg+xml'));
    }

    public function testSvgzIsSandboxed(): void
    {
        $this->assertArrayHasKey('Content-Security-Policy', $this->headersFor('svgz'));
    }

    public function testTypeMatchIsCaseInsensitive(): void
    {
        $this->assertArrayHasKey('Content-Security-Policy', $this->headersFor('SVG'));
    }

    /**
     * @dataProvider rasterTypes
     */
    public function testRasterTypesAreUntouched($type): void
    {
        $this->assertSame([], $this->headersFor($type));
    }

    public function rasterTypes(): array
    {
        return [['png'], ['jpg'], ['jpeg'], ['gif'], ['webp'], ['image/png'], [''], [null]];
    }
}
