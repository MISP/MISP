<?php
/**
 * Stubs and a recording CakeResponse for RestResponseCursorCorsTest.
 *
 * Loaded only from the test's setUp(), which runs in a separate process: the
 * unguarded App/Configure/Component stubs here would otherwise collide with
 * the stubs other files under app/Test/ declare in the shared PHPUnit process.
 */

class Component {}
class App
{
    public static function uses($class, $package) {}
}
class Configure
{
    public static $cors = false;

    public static function read($key)
    {
        if ($key === 'Security.allow_cors') {
            return self::$cors;
        }
        if ($key === 'Security.cors_origins') {
            return 'https://client.example';
        }
        return false;
    }
}
class CakeResponse
{
    public $headers = [];
    public $options;

    public function __construct($options)
    {
        $this->options = $options;
    }

    public function header($headers)
    {
        $this->headers = array_merge($this->headers, $headers);
    }
}
require_once __DIR__ . '/../Controller/Component/RestResponseComponent.php';
