<?php
/** Framework doubles loaded only inside isolated controller test processes. */

if (!class_exists('App', false)) {
    class App { public static function uses($class, $package) {} }
}
if (!class_exists('Component', false)) {
    class Component {}
}
if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = [];
        public static function read($key) { return self::$values[$key] ?? null; }
        public static function write($key, $value) { self::$values[$key] = $value; }
    }
}
if (!function_exists('__')) {
    function __($message, ...$args) { return $args ? vsprintf($message, $args) : $message; }
}
if (!class_exists('HttpException', false)) {
    class HttpException extends RuntimeException {}
    class BadRequestException extends HttpException
    {
        public function __construct($message) { parent::__construct($message, 400); }
    }
    class ForbiddenException extends HttpException
    {
        public function __construct($message) { parent::__construct($message, 403); }
    }
    class MethodNotAllowedException extends HttpException
    {
        public function __construct($message) { parent::__construct($message, 405); }
    }
}
if (!class_exists('AppController', false)) {
    class AppController
    {
        public $request;
        public $response;
        public $Auth;
        public $MispAttribute;
        public $RestResponse;
        public $Security;
        public $RequestHandler;
        public $Job;
        public $Server;
        public $viewVars = [];
        public $rest = true;
        public $admin = true;
        protected function _isSiteAdmin() { return $this->admin; }
        public function beforeFilter() {}
        protected function _csrfTokenHeaderOnly(array $actions) {}
        protected function _isRest() { return $this->rest; }
        public function set($name, $value) { $this->viewVars[$name] = $value; }
        public function loadModel($name) { $this->{$name} = new $name(); }
    }
}
if (!class_exists('CakeResponse', false)) {
    class CakeResponse
    {
        public $headers = [];
        private $options;
        public function __construct(array $options = []) { $this->options = $options; }
        public function header($header = null, $value = null)
        {
            if (is_array($header)) {
                $this->headers = array_merge($this->headers, $header);
            } elseif ($header !== null) {
                $this->headers[$header] = $value;
            }
            return $this->headers;
        }
        public function body() { return $this->options['body'] ?? ''; }
        public function statusCode() { return $this->options['status'] ?? 200; }
        public function type() { return $this->options['type'] ?? null; }
    }
}

require_once __DIR__ . '/../../Lib/Tools/JsonTool.php';
// An unrelated legacy action declares an optional argument before a required
// one. Loading the controller inside setUp exposes its compile-time PHP 8
// deprecation; keep that warning out of this isolated test process's protocol.
$previousErrorReporting = error_reporting(error_reporting() & ~E_DEPRECATED);
try {
    require_once __DIR__ . '/../../Controller/AttributesController.php';
} finally {
    error_reporting($previousErrorReporting);
}
require_once __DIR__ . '/../../Controller/Component/RestResponseComponent.php';
require_once __DIR__ . '/../../Controller/Component/RateLimitComponent.php';

class FastLookupControllerRequest
{
    public $data = ['value' => ['example.org']];
    public $method = 'POST';
    public $contentType = 'application/json';
    public $action = 'fastLookup';
    public $query = [];
    public $params = ['action' => 'fastLookup', 'named' => []];
    public function is($method) { return strtolower($this->method) === strtolower($method); }
    public function allowMethod(array $methods)
    {
        if (!in_array(strtolower($this->method), $methods, true)) {
            throw new MethodNotAllowedException('Method not allowed');
        }
    }
    public function header($name) { return $name === 'Content-Type' ? $this->contentType : null; }
}

class FastLookupControllerRequestHandler
{
    public $callbacks = [];
    public function addInputType($type, array $callback) { $this->callbacks[$type] = $callback; }
}

class FastLookupControllerModel
{
    public $typeDefinitions;
    public $calls = [];
    public $result;
    public $exception;
    public function __construct() { $this->typeDefinitions = array_fill_keys(FastLookupConfig::DEFAULT_TYPES, []); }
    public function fastLookup(array $user, array $request): array
    {
        $this->calls[] = [$user, $request];
        if ($this->exception) {
            throw $this->exception;
        }
        return $this->result ?? ['status' => 'ready', 'scope' => FastLookupConfig::scope($this), 'results' => new stdClass()];
    }
}

class ClassRegistry
{
    public static function init($name) { return new FastLookupControllerModel(); }
}
require_once __DIR__ . '/../../Lib/Tools/FastLookupConfig.php';
