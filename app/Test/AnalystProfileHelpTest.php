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
        $arguments = array_slice(func_get_args(), 1);
        return empty($arguments) ? $singular : vsprintf($singular, $arguments);
    }
}
require_once __DIR__ . '/../Lib/Tools/WarninglistCategory.php';
require_once __DIR__ . '/../Lib/Tools/ValueIntelligence/ValueExclusionTool.php';
require_once __DIR__ . '/../Model/ValueSignals/ValueSignalBase.php';
require_once __DIR__ . '/../Model/ValueEscalations/ValueEscalationBase.php';

use PHPUnit\Framework\TestCase;

/**
 * The "How it works" popovers fill `{key}` from a row's settings and list
 * each setting beside its explanation, so a renamed setting has to fail
 * here rather than print a literal `{key}` in the editor.
 */
class AnalystProfileHelpTest extends TestCase
{
    private static function configs($directory, $base)
    {
        $configs = array();
        $files = glob(__DIR__ . '/../Model/' . $directory . '/*.php');
        foreach ($files as $file) {
            $class = basename($file, '.php');
            if ($class === $base) {
                continue;
            }
            require_once $file;
            $instance = new $class();
            $configs[$instance->id] = $instance->getConfig();
        }
        ksort($configs);
        return $configs;
    }

    public function signals()
    {
        $cases = array();
        foreach (self::configs('ValueSignals', 'ValueSignalBase')
            as $id => $c
        ) {
            $cases[$id] = array($id, $c['description'], $c['help'],
                array_merge(array_keys($c['points_schema']),
                    array_keys($c['config_schema'])), true);
        }
        return $cases;
    }

    public function conflictRules()
    {
        $cases = array();
        foreach (self::configs('ValueEscalations', 'ValueEscalationBase')
            as $id => $c
        ) {
            $cases[$id] = array($id, $c['description'], $c['help'],
                array_keys($c['when_schema']), true);
        }
        return $cases;
    }

    public function exclusions()
    {
        $cases = array();
        foreach (ValueExclusionTool::catalogue() as $id => $declaration) {
            $cases[$id] = array($id, $declaration['description'],
                $declaration['help'], array_keys($declaration['schema']),
                false);
        }
        return $cases;
    }

    /**
     * @dataProvider signals
     * @dataProvider conflictRules
     * @dataProvider exclusions
     */
    public function testHelpNamesOnlyRealSettingsAndExplainsEach(
        $id, $description, $help, array $keys, $named
    ) {
        $this->assertIsString($description);
        $this->assertNotSame('', trim($description), $id);
        $this->assertNotSame('to-override', $description, $id);
        $this->assertIsArray($help, $id);
        $required = array('what', 'how', 'recipes');
        if ($named) {
            $required[] = 'name';
        }
        foreach ($required as $part) {
            $this->assertNotEmpty($help[$part] ?? null, "$id: no `$part`");
        }

        $settings = isset($help['settings']) ? $help['settings'] : array();
        $this->assertSame(
            array(),
            array_values(array_diff(array_keys($settings), $keys)),
            "$id: explains a setting it does not have"
        );
        $this->assertSame(
            array(),
            array_values(array_diff($keys, array_keys($settings))),
            "$id: leaves a setting unexplained"
        );

        $texts = array_merge(
            array($help['what'], $help['how'], $help['note'] ?? ''),
            array_values($settings)
        );
        foreach ($help['recipes'] as $recipe) {
            $this->assertNotEmpty($recipe['want'] ?? null, "$id: recipe");
            $this->assertNotEmpty($recipe['do'] ?? null, "$id: recipe");
            $texts[] = $recipe['want'];
            $texts[] = $recipe['do'];
        }
        foreach ($texts as $text) {
            preg_match_all('/\{([a-z0-9_]+)\}/', $text, $m);
            $this->assertSame(
                array(),
                array_values(array_diff($m[1], $keys)),
                "$id: a {token} names no setting in: $text"
            );
        }
    }

    /**
     * Help sends a reader to other rows by id; those ids have to exist.
     */
    public function testIdsNamedInHelpExist()
    {
        $help = array();
        foreach (array($this->signals(), $this->conflictRules(),
            $this->exclusions()) as $cases
        ) {
            foreach ($cases as $id => $case) {
                $help[$id] = $case[2];
            }
        }
        $known = array_keys($help);
        foreach ($help as $id => $text) {
            preg_match_all(
                '/\b(conflict:[a-z-]+|[a-z_]{3,}\.[a-z_]{3,})\b/',
                json_encode($text),
                $m
            );
            $this->assertSame(
                array(),
                array_values(array_diff(array_unique($m[1]), $known)),
                "$id: names a row that does not exist"
            );
        }
    }
}
