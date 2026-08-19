<?php

use PHPUnit\Framework\TestCase;

if (!function_exists('__')) {
    // Fake translation function
    function __($singular, $args = null)
    {
        $arguments = func_get_args();
        return vsprintf($singular, array_slice($arguments, 1));
    }
}

if (!function_exists('env')) {
    // Only the $_SERVER lookup matters for the code under test
    function env($key)
    {
        return isset($_SERVER[$key]) ? $_SERVER[$key] : null;
    }
}

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

if (!class_exists('BadRequestException', false)) {
    class BadRequestException extends RuntimeException
    {
    }
}

if (!class_exists('Controller', false)) {
    class Controller
    {
        public $here = '/feeds/enable/2';
    }
}

if (!class_exists('SecurityComponent', false)) {
    /**
     * Stands in for Cake's SecurityComponent. startup() records that it was
     * reached, which is the observable that matters: the whole point of the
     * fix is that an unsafe override never gets that far.
     */
    class SecurityComponent
    {
        public $startupReached = false;
        public $logged = [];

        public function startup(Controller $controller)
        {
            $this->startupReached = true;
            return true;
        }

        public function log($message)
        {
            $this->logged[] = $message;
        }
    }
}

require_once __DIR__ . '/../Controller/Component/BetterSecurityComponent.php';

/**
 * Cake honours a `_method` field in the POST body by rewriting REQUEST_METHOD,
 * and for any verb outside POST/PUT/PATCH/DELETE it also empties the request
 * body. SecurityComponent then sees no data and skips form security entirely,
 * so `_method=GET` in a cross-site form post disabled CSRF validation for every
 * action taking its input from the URL.
 */
class BetterSecurityComponentTest extends TestCase
{
    /** @var BetterSecurityComponent */
    private $component;

    /** @var Controller */
    private $controller;

    protected function setUp(): void
    {
        $_POST = [];
        unset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
        $this->component = new BetterSecurityComponent();
        $this->controller = new Controller();
    }

    protected function tearDown(): void
    {
        $_POST = [];
        unset($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
    }

    /**
     * The four verbs Cake acts on without discarding the body. MISP's own forms
     * emit these (the login form posts `_method=POST`), so they must survive.
     */
    public function testWriteVerbOverridesArePassedThrough(): void
    {
        foreach (['POST', 'PUT', 'PATCH', 'DELETE'] as $verb) {
            $this->setUp();
            $_POST['_method'] = $verb;
            $this->component->startup($this->controller);
            $this->assertTrue(
                $this->component->startupReached,
                "_method=$verb must reach the regular form security checks"
            );
        }
    }

    public function testNoOverrideIsPassedThrough(): void
    {
        $_POST['x'] = '1';
        $this->component->startup($this->controller);
        $this->assertTrue($this->component->startupReached);
    }

    /**
     * The bypass itself: any verb outside the write set makes Cake empty the
     * body, which is what let the request slip past $hasData.
     */
    public function testNonWriteVerbOverrideIsRefused(): void
    {
        foreach (['GET', 'HEAD', 'OPTIONS', 'TRACE', 'get', 'Get', ''] as $verb) {
            $this->setUp();
            $_POST['_method'] = $verb;
            $refused = false;
            try {
                $this->component->startup($this->controller);
            } catch (BadRequestException $e) {
                $refused = true;
            }
            $this->assertTrue($refused, "_method=" . var_export($verb, true) . " must be refused");
            $this->assertFalse(
                $this->component->startupReached,
                'the request must be refused before form security is evaluated'
            );
        }
    }

    /**
     * `_method[]=GET` misses Cake's in_array() check the same way an unexpected
     * verb does, so the body is emptied just the same.
     */
    public function testNonStringOverrideIsRefused(): void
    {
        $_POST['_method'] = ['GET'];
        $this->expectException(BadRequestException::class);
        $this->component->startup($this->controller);
    }

    public function testHeaderOverrideIsRefused(): void
    {
        $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] = 'GET';
        $_POST['x'] = '1';
        $this->expectException(BadRequestException::class);
        $this->component->startup($this->controller);
    }

    /**
     * _processPost() lets the header win over the body, so a safe-looking body
     * must not launder an unsafe header.
     */
    public function testHeaderOverrideWinsOverSafeBodyOverride(): void
    {
        $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] = 'GET';
        $_POST['_method'] = 'POST';
        $this->expectException(BadRequestException::class);
        $this->component->startup($this->controller);
    }

    public function testHeaderOverrideWithWriteVerbIsPassedThrough(): void
    {
        $_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] = 'DELETE';
        $this->component->startup($this->controller);
        $this->assertTrue($this->component->startupReached);
    }

    public function testRefusalIsLogged(): void
    {
        $_POST['_method'] = 'GET';
        try {
            $this->component->startup($this->controller);
        } catch (BadRequestException $e) {
            // expected
        }
        $this->assertCount(1, $this->component->logged);
        $this->assertStringContainsString('/feeds/enable/2', $this->component->logged[0]);
        $this->assertStringContainsString('GET', $this->component->logged[0]);
    }
}
