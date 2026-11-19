<?php

namespace MispTest\Support;

/**
 * Framework stubs for MISP's unit test layer.
 *
 * Unit tests run with no CakePHP bootstrap, no database and no HTTP. The
 * classes below stand in for the framework surface that MISP source files
 * touch at load time. Every stub is declared only when the real class is
 * absent, so a test that loads the genuine CakePHP class keeps the genuine
 * behaviour.
 */
class FrameworkStubs
{
    /** @var bool */
    private static $installed = false;

    /**
     * Constants only. Callable before loadRealParents(), which needs APP.
     */
    public static function defineConstants(): void
    {
        if (!defined('DS'))       { define('DS', DIRECTORY_SEPARATOR); }
        if (!defined('APP'))      { define('APP', dirname(dirname(__DIR__)) . DS); }
        if (!defined('ROOT'))     { define('ROOT', dirname(dirname(dirname(__DIR__)))); }
        // WWW_ROOT and TMP are deliberately NOT defined here: they are I/O
        // roots that individual tests redirect at a temp directory, and a
        // global definition would win over the test's own.
    }

    public static function install(): void
    {
        if (self::$installed) {
            return;
        }
        self::$installed = true;
        self::defineConstants();

        if (!class_exists('App', false)) {
            eval('class App {
                public static function uses($a = null, $b = null) {}
                public static function import($a = null, $b = null) {}
                public static function path($a = null, $b = null) { return []; }
            }');
        }
        if (!class_exists('Configure', false)) {
            eval('class Configure {
                private static $d = [];
                public static function read($k = null) { return self::$d[$k] ?? null; }
                public static function write($k, $v = null) { self::$d[$k] = $v; }
                public static function check($k) { return isset(self::$d[$k]); }
                public static function delete($k) { unset(self::$d[$k]); }
                public static function reset() { self::$d = []; }
            }');
        }
        if (!class_exists('ClassRegistry', false)) {
            eval('class ClassRegistry {
                public static $instances = [];
                /** @var callable|null Test-supplied factory: fn(string $name): object */
                public static $factory = null;
                public static function init($name) {
                    if (!isset(self::$instances[$name])) {
                        self::$instances[$name] = self::$factory
                            ? call_user_func(self::$factory, $name)
                            : new \stdClass();
                    }
                    return self::$instances[$name];
                }
                public static function addObject($name, $object) { self::$instances[$name] = $object; }
                public static function reset() { self::$instances = []; self::$factory = null; }
                public static function flush() { self::$instances = []; }
            }');
        }

        $simple = [
            'Component'     => 'class Component { public function __construct($c = null, $s = []) {} public function initialize($c = null) {} }',
            'ComponentCollection' => 'class ComponentCollection {}',
            'Helper'        => 'class Helper {
                public $helpers = [];
                private $__injected = [];
                public function __construct($v = null, $s = []) {}
                // CakePHP injects the helpers named in $helpers as properties.
                // A permissive stand-in lets a helper that composes others run.
                public function __get($name) {
                    if (!isset($this->__injected[$name])) {
                        $this->__injected[$name] = new \\MispTest\\Support\\FakeModel();
                    }
                    return $this->__injected[$name];
                }
                public function __isset($name) { return true; }
            }',
            'Model'         => 'class Model { public $name; public $id; public $data = []; public $validationErrors = []; public $useTable; public $alias; public function __construct($i = false, $t = null, $d = null) {} }',
            'Shell'         => 'class Shell { public function __construct($o = null, $c = null) {} }',
            'Controller'    => 'class Controller {}',
            'ModelBehavior' => 'class ModelBehavior {}',
            'CakeObject'    => 'class CakeObject {}',
            'BehaviorCollection' => 'class BehaviorCollection {}',
        ];
        foreach ($simple as $class => $decl) {
            if (!class_exists($class, false)) { eval($decl); }
        }

        if (!class_exists('AppModel', false))      { eval('class AppModel extends Model {}'); }
        if (!class_exists('AppController', false)) { eval('class AppController extends Controller {}'); }
        if (!class_exists('AppShell', false))      { eval('class AppShell extends Shell {}'); }

        if (!class_exists('CakeText', false)) {
            eval('class CakeText {
                public static function tokenize($d, $s = ",", $l = "(", $r = ")") { return explode($s, $d); }
                public static function uuid() {
                    return sprintf("%04x%04x-%04x-4%03x-%04x-%04x%04x%04x",
                        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff),
                        mt_rand(0, 0x0fff), mt_rand(0, 0x3fff) | 0x8000,
                        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff));
                }
                public static function insert($str, $data, $options = []) { return $str; }
                public static function cleanInsert($str, $options = []) { return $str; }
            }');
        }
        if (!class_exists('Inflector', false)) {
            eval('class Inflector {
                public static function underscore($s) { return strtolower(preg_replace("/(?<!^)[A-Z]/", "_$0", $s)); }
                public static function camelize($s) { return str_replace(" ", "", ucwords(str_replace("_", " ", $s))); }
                public static function pluralize($s) { return $s . "s"; }
                public static function singularize($s) { return rtrim($s, "s"); }
                public static function humanize($s) { return str_replace("_", " ", ucwords($s, "_")); }
                public static function tableize($s) { return strtolower(preg_replace("/(?<!^)[A-Z]/", "_$0", $s)) . "s"; }
                public static function classify($s) { return str_replace(" ", "", ucwords(str_replace("_", " ", rtrim($s, "s")))); }
                public static function variable($s) { return lcfirst(str_replace(" ", "", ucwords(str_replace("_", " ", $s)))); }
                public static function slug($s, $r = "-") { return preg_replace("/[^a-zA-Z0-9]+/", $r, $s); }
            }');
        }
        if (!class_exists('CakeLog', false)) {
            eval('class CakeLog {
                public static $lines = [];
                public static function write($a, $b) { self::$lines[] = [$a, $b]; }
            }');
        }
        if (!class_exists('Router', false)) {
            eval('class Router { public static function url($u = null, $f = false) { return is_string($u) ? $u : "/"; } }');
        }
        if (!class_exists('Hash', false)) {
            // Enough of Cake's Hash surface for constructors to run. Anything
            // whose behaviour a test actually asserts should use the real data
            // rather than relying on these returning empty.
            eval('class Hash {
                public static function extract($d, $p) { return []; }
                public static function get($d, $p, $def = null) { return $def; }
                public static function combine($d, $k, $v = null, $g = null) { return []; }
                public static function merge($d, $m) { return is_array($d) ? $d : []; }
                public static function insert($d, $p, $v = null) { return $d; }
                public static function remove($d, $p) { return $d; }
                public static function sort($d, $p, $dir = "asc", $type = "regular") { return $d; }
                public static function filter($d, $cb = null) { return is_array($d) ? array_filter($d) : []; }
                public static function map($d, $p, $f) { return []; }
                public static function apply($d, $p, $f) { return []; }
                public static function numeric($a) { return false; }
                public static function dimensions($d) { return 1; }
                public static function maxDimensions($d) { return 1; }
                public static function normalize($d, $assoc = true) { return is_array($d) ? $d : []; }
            }');
        }

        $simple2 = [
            'CakeResponse'           => 'class CakeResponse { public function __construct($o = []) {} public function file($p, $opt = []) {} public function send() {} }',
            'CakeRequest'            => 'class CakeRequest { public function __construct($u = null, $p = true) {} }',
            'HttpSocket'             => 'class HttpSocket { public function __construct($c = []) {} public function get($u = null, $q = [], $r = []) {} public function post($u = null, $d = [], $r = []) {} }',
            'HttpSocketResponse'     => 'class HttpSocketResponse { public $code = 200; public $body = ""; public function body() { return $this->body; } public function isOk() { return $this->code === 200; } }',
            'CakeEmail'              => 'class CakeEmail { public function __construct($c = null) {} }',
            'CakeEventManager'       => 'class CakeEventManager { public function attach($c = null, $e = null, $o = []) {} public function dispatch($event) {} }',
            'CakeSession'            => 'class CakeSession { public static function read($k = null) { return null; } public static function write($k, $v = null) {} }',
            'Folder'                 => 'class Folder { public function __construct($p = null, $c = false, $m = false) {} }',
            'File'                   => 'class File {
                public $path;
                private $buffer = "";
                public function __construct($p = null, $c = false, $m = 0755) { $this->path = $p; }
                public function write($data, $mode = "w", $force = false) { $this->buffer = $data; return true; }
                public function append($data, $force = false) { $this->buffer .= $data; return true; }
                public function read($bytes = false, $mode = "rb", $force = false) { return $this->buffer; }
                public function delete() { return true; }
                public function create() { return true; }
                public function close() { return true; }
                public function exists() { return true; }
                public function name() { return basename((string)$this->path); }
                public function size() { return strlen($this->buffer); }
            }',
            'Validation'             => 'class Validation { public static function ip($v) { return filter_var($v, FILTER_VALIDATE_IP) !== false; } public static function url($v) { return filter_var($v, FILTER_VALIDATE_URL) !== false; } }',
            'Set'                    => 'class Set {}',
            'Xml'                    => 'class Xml {
                public static function build($d, $o = []) { return null; }
                public static function toArray($x) { return []; }
                public static function fromArray($input, $options = []) {
                    $w = new \\XMLWriter(); $w->openMemory(); $w->startDocument("1.0", "UTF-8");
                    $write = function ($data, $parent) use (&$write, $w) {
                        foreach ((array)$data as $key => $value) {
                            $name = is_numeric($key) ? $parent : (string)$key;
                            if (is_array($value) || is_object($value)) {
                                $w->startElement($name); $write($value, $name); $w->endElement();
                            } else {
                                $w->writeElement($name, (string)$value);
                            }
                        }
                    };
                    $write($input, "item");
                    $w->endDocument();
                    return new \\SimpleXMLElement($w->outputMemory() ?: "<root/>");
                }
            }',
            'ConnectionManager'      => 'class ConnectionManager { public static function getDataSource($n = null) { return new \\stdClass(); } }',
            'DboSource'              => 'class DboSource {}',
        ];
        foreach ($simple2 as $class => $decl) {
            if (!class_exists($class, false)) { eval($decl); }
        }
        // These extend a stubbed base, so they must be declared after it.
        if (!class_exists('AuthComponent', false))          { eval('class AuthComponent extends Component { public static $sessionKey = "Auth.User"; }'); }
        if (!class_exists('SecurityComponent', false))      { eval('class SecurityComponent extends Component {}'); }
        if (!class_exists('PaginatorHelper', false))        { eval('class PaginatorHelper extends Helper {}'); }
        if (!class_exists('BaseAuthenticate', false))       { eval('class BaseAuthenticate { public function __construct($c = null, $s = []) {} }'); }
        if (!class_exists('AbstractPasswordHasher', false)) { eval('class AbstractPasswordHasher { public function __construct($c = []) {} }'); }

        // Resolve MISP's own Lib classes on demand. Source files declare their
        // dependencies with App::uses(), which is a no-op here, so without this
        // any collaborator a unit reaches for at runtime is simply missing.
        spl_autoload_register(static function ($class) {
            if (strpos($class, '\\') !== false) {
                return; // namespaced: not MISP's global Lib classes
            }
            static $dirs = [
                'Lib/Tools/',
                'Lib/Dashboard/',
                'Lib/Dashboard/Tools/',
                'Lib/Export/',
                'Lib/Tools/BackgroundJobs/',
            ];
            foreach ($dirs as $dir) {
                $file = APP . $dir . $class . '.php';
                if (is_file($file)) {
                    require_once $file;
                    return;
                }
            }
        });

        // CakePHP's global helper functions. MISP source calls __() pervasively;
        // without it, any constructor that builds a translated label fatals.
        if (!function_exists('__')) {
            eval('function __($s, $args = null) {
                if ($args === null) { return $s; }
                if (!is_array($args)) { $args = array_slice(func_get_args(), 1); }
                return vsprintf($s, $args);
            }');
        }
        if (!function_exists('__n')) {
            eval('function __n($s, $p, $c, $args = null) { return $c === 1 ? $s : $p; }');
        }
        if (!function_exists('h')) {
            eval('function h($text, $double = true, $charset = null) {
                return is_string($text) ? htmlspecialchars($text, ENT_QUOTES, "UTF-8", $double) : $text;
            }');
        }
        if (!function_exists('pr')) {
            eval('function pr($var) { return null; }');
        }
        if (!function_exists('debug')) {
            eval('function debug($var, $showHtml = null, $showFrom = true) { return null; }');
        }

        foreach ([
            'CakeException', 'NotFoundException', 'MethodNotAllowedException',
            'InternalErrorException', 'ForbiddenException', 'UnauthorizedException',
        ] as $e) {
            if (!class_exists($e, false)) { eval("class $e extends \\Exception {}"); }
        }
    }

    /**
     * Some source files extend a real CakePHP or in-repo class that no stub
     * can stand in for. Load the genuine parent before including the file.
     */
    public static function loadRealParents(string $file): void
    {
        $inRepo = [
            'Model/WorkflowModules'       => [APP . 'Model/WorkflowModules/WorkflowBaseModule.php'],
            'Lib/Export/Nids'             => [APP . 'Lib/Export/NidsExport.php'],
            'Lib/Export/Stix'             => [APP . 'Lib/Export/StixExport.php'],
            'Lib/Export/Context'          => [APP . 'Lib/Export/ContextExport.php'],
            'Module_splunk_hec_export'    => [APP . 'Model/WorkflowModules/action/Module_webhook.php'],
            'Lib/Tools/CurlClient'        => [APP . 'Lib/Tools/HttpSocketExtended.php'],
        ];
        foreach ($inRepo as $needle => $parents) {
            if (strpos($file, $needle) === false) {
                continue;
            }
            foreach ($parents as $parent) {
                if ($parent !== $file && is_file($parent)) {
                    require_once $parent;
                }
            }
        }

        // MISP's own AppHelper is the parent of every View/Helper class. It is
        // in-repo code, so it is loaded for real rather than stubbed.
        if (strpos($file, 'View/Helper') !== false) {
            $appHelper = APP . 'View/Helper/AppHelper.php';
            if ($appHelper !== $file && !class_exists('AppHelper', false) && is_file($appHelper)) {
                require_once $appHelper;
            }
        }
    }
}
