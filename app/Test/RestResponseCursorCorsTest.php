<?php
/** Exercise actual response preparation with a recording CakeResponse. */
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class RestResponseCursorCorsTest extends TestCase
{
    protected function setUp(): void
    {
        require_once __DIR__ . '/RestResponseCursorCorsFixtures.php';
    }

    protected function tearDown(): void
    {
        Configure::$cors = false;
    }

    private function response()
    {
        $component = (new ReflectionClass(RestResponseComponent::class))
            ->newInstanceWithoutConstructor();
        return $component->viewData('{}', 'json', false, true, false, [
            'X-Result-Count' => 2,
            'X-Next-Cursor' => '5',
            'X-Has-More' => 'true',
        ]);
    }

    public function testCorsExposesCursorContinuationHeaders()
    {
        Configure::$cors = true;
        $response = $this->response();
        $exposed = $response->headers['Access-Control-Expose-Headers'];
        $this->assertContains('X-Result-Count', $exposed);
        $this->assertContains('X-Next-Cursor', $exposed);
        $this->assertContains('X-Has-More', $exposed);
        $this->assertSame('5', $response->headers['X-Next-Cursor']);
        $this->assertSame('true', $response->headers['X-Has-More']);
        $this->assertSame('{}', $response->options['body']);
    }

    public function testDisabledCorsDoesNotExposeHeaders()
    {
        $response = $this->response();
        $this->assertArrayNotHasKey(
            'Access-Control-Expose-Headers', $response->headers
        );
        $this->assertSame('5', $response->headers['X-Next-Cursor']);
    }
}
