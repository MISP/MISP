<?php
/**
 * Warninglist regex evaluation bound and import validation tests.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

if (!defined('APP')) {
    define('APP', dirname(__DIR__) . '/');
}

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

if (!class_exists('CakeLog', false)) {
    class CakeLog
    {
        public static function __callStatic($name, $arguments)
        {
        }
    }
}

if (!function_exists('__')) {
    function __($singular, ...$args)
    {
        return vsprintf($singular, $args);
    }
}

require_once __DIR__ . '/../Lib/Tools/CidrTool.php';

class WarninglistRegexBoundModelStub
{
}

class WarninglistRegexBoundSpy
{
    public $calls = [];

    public function __call($name, $arguments)
    {
        $this->calls[] = $name;
        return true;
    }
}

class WarninglistRegexBoundTest extends TestCase
{
    // Needs ~100k-1M backtracking steps before the second alternative matches
    const SLOW_PATTERN = '/^(a+)+$|^a/';
    const SLOW_VALUE = 'aaaaaaaaaaaaaaaaab';

    private static function model()
    {
        // Loaded at run time: an AppModel stub declared while the suite loads
        // would win over the one other tests need.
        if (!class_exists('AppModel', false)) {
            class_alias('WarninglistRegexBoundModelStub', 'AppModel');
        }
        if (!class_exists('WarninglistRegexBoundModel', false)) {
            require_once __DIR__ . '/../Model/Warninglist.php';
            eval('class WarninglistRegexBoundModel extends Warninglist {
                public $logged = [];
                public $entrySpy;
                protected function logFailedRegex($pattern) { $this->logged[] = $pattern; }
                public function find($type = "first", $query = []) {
                    return ["Warninglist" => ["id" => 7, "name" => "x", "default" => 0, "enabled" => 1]];
                }
                public function create($data = [], $filterKey = false) {}
                public function save($data = null, $validate = true, $fieldList = []) { throw new Exception("Could not save warninglist"); }
                public function __get($name) { return $this->entrySpy; }
                public function eval($listValues, $value) {
                    return $this->checkValue($listValues, $value, "ip-src", "regex");
                }
            }');
        }
        $reflection = new ReflectionClass('WarninglistRegexBoundModel');
        $model = $reflection->newInstanceWithoutConstructor();
        $model->entrySpy = new WarninglistRegexBoundSpy();
        return $model;
    }

    public function testBacktrackingBeyondTheBoundIsNoMatchAndLoggedOnce()
    {
        $model = self::model();
        $this->assertFalse($model->eval([self::SLOW_PATTERN], self::SLOW_VALUE));
        $this->assertFalse($model->eval([self::SLOW_PATTERN], self::SLOW_VALUE));
        $this->assertSame([self::SLOW_PATTERN], $model->logged);
    }

    public function testFailedPatternIsSkippedForLaterValuesAndOthersStillMatch()
    {
        $model = self::model();
        $patterns = [self::SLOW_PATTERN, '/^foo\d+$/'];
        $this->assertFalse($model->eval($patterns, self::SLOW_VALUE));
        // The skipped pattern would match this value if it were evaluated
        $this->assertSame(['/^foo\d+$/', 'foo42'], $model->eval($patterns, 'foo42'));
        $this->assertFalse($model->eval([self::SLOW_PATTERN], 'a'));
    }

    public function testBacktrackLimitIsRestored()
    {
        $before = ini_get('pcre.backtrack_limit');
        $model = self::model();
        $model->eval([self::SLOW_PATTERN], self::SLOW_VALUE);
        $this->assertSame($before, ini_get('pcre.backtrack_limit'));
        $model->eval(['/^foo$/'], 'foo');
        $this->assertSame($before, ini_get('pcre.backtrack_limit'));
    }

    public function testImportRejectsInvalidRegexBeforeTouchingExistingEntries()
    {
        $model = self::model();
        $list = ['name' => 'x', 'type' => 'regex', 'list' => ['/ok/', '/(unclosed']];
        try {
            $model->import($list);
            $this->fail('Import of an invalid regex was accepted');
        } catch (Exception $e) {
            $this->assertStringContainsString('not valid regular expression', $e->getMessage());
        }
        $this->assertSame([], $model->entrySpy->calls);
    }

    public function testImportRejectsInvalidCidrInAMapWithComments()
    {
        $model = self::model();
        $list = ['name' => 'x', 'type' => 'cidr', 'list' => ['192.0.2.0/24' => 'ok', 'nonsense' => 'bad']];
        try {
            $model->import($list);
            $this->fail('Import of an invalid CIDR was accepted');
        } catch (Exception $e) {
            $this->assertStringContainsString('not valid CIDR', $e->getMessage());
        }
        $this->assertSame([], $model->entrySpy->calls);
    }
}
