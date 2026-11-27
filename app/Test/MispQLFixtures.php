<?php
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        $arguments = array_slice(func_get_args(), 1);
        return $arguments ? vsprintf($singular, $arguments) : $singular;
    }
}
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLCompiler.php';
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLRows.php';

/**
 * Shared by the MispQL tests. The models' REST_SEARCH_ORDER_FIELDS and the
 * field registries are read from their source rather than by loading the
 * classes: other tests declare stand-ins for model classes (MispAttribute)
 * in the same PHPUnit process.
 */
class MispQLFixtures
{
    /**
     * Where MispQLCakeBackend's validator for each table finds its fields:
     * files, each with the tokens the field array follows.
     */
    const FIELD_SOURCES = [
        'attributes' => [['Lib/Tools/ComplexQueryTool.php', ['const', 'FIELDS', '=']]],
        'events' => [['Lib/Tools/ComplexEventQueryTool.php', ['const', 'FIELDS', '=']]],
        'objects' => [['Lib/Tools/ComplexObjectQueryTool.php', ['const', 'FIELDS', '=']]],
        'galaxy_clusters' => [['Model/GalaxyCluster.php', ['const', 'QUERY_FIELDS', '=']]],
        'event_reports' => [['Model/EventReport.php', ['const', 'QUERY_FIELDS', '=']]],
        'notes' => [
            ['Model/AnalystData.php', ['function', 'queryFields', '$fields', '=']],
            ['Model/Note.php', ['const', 'QUERY_FIELDS', '=']],
        ],
        'opinions' => [
            ['Model/AnalystData.php', ['function', 'queryFields', '$fields', '=']],
            ['Model/Opinion.php', ['const', 'QUERY_FIELDS', '=']],
        ],
        'relationships' => [
            ['Model/AnalystData.php', ['function', 'queryFields', '$fields', '=']],
            ['Model/Relationship.php', ['const', 'QUERY_FIELDS', '=']],
        ],
        'collections' => [['Model/Collection.php', ['const', 'QUERY_FIELDS', '=']]],
        'tags' => [['Model/Tag.php', ['const', 'QUERY_FIELDS', '=']]],
        'organisations' => [['Model/Organisation.php', ['const', 'QUERY_FIELDS', '=']]],
    ];

    /** @var array */
    private static $orderFields = [];

    /**
     * @param string $table
     * @return string[] the fields MISP describes for the table, a wildcard
     *   named `meta.<key>` as queryDescribe names it
     */
    public static function fieldNames($table)
    {
        $names = [];
        foreach (self::FIELD_SOURCES[$table] as list($file, $anchor)) {
            foreach (self::arrayKeys(__DIR__ . "/../$file", $anchor) as $name) {
                $names[] = str_ends_with($name, '.*') ? substr($name, 0, -1) . '<key>' : $name;
            }
        }
        return $names;
    }

    /**
     * @param string $model
     * @return array
     */
    public static function orderFields($model)
    {
        if (!isset(self::$orderFields[$model])) {
            self::$orderFields[$model] = self::readConstant(
                __DIR__ . "/../Model/$model.php",
                'REST_SEARCH_ORDER_FIELDS'
            );
        }
        return self::$orderFields[$model];
    }

    /**
     * @return MispQLTables
     */
    public static function tables()
    {
        return new MispQLTables([self::class, 'orderFields']);
    }

    /**
     * @return MispQLCompiler
     */
    public static function compiler()
    {
        return new MispQLCompiler(self::tables());
    }

    /**
     * A plan with each span as start, end and the text between them.
     *
     * @param array $plan
     * @param string $text
     * @return array
     */
    public static function withFragments(array $plan, $text)
    {
        foreach ($plan['spans'] as $path => $span) {
            $plan['spans'][$path] = self::located($span, $text);
        }
        return $plan;
    }

    /**
     * @param array $span [start, end]
     * @param string $text
     * @return array
     */
    public static function located(array $span, $text)
    {
        return [
            'start' => $span[0],
            'end' => $span[1],
            'fragment' => MispQLLexer::slice($text, $span[0], $span[1]),
        ];
    }

    /**
     * The string keys of the array literal that follows the anchor tokens,
     * from the file holding it.
     *
     * @param string $file
     * @param string[] $anchor token texts, in order, whitespace aside
     * @return string[]
     */
    private static function arrayKeys($file, array $anchor)
    {
        $tokens = array_values(array_filter(token_get_all(file_get_contents($file)), function ($t) {
            return !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
        }));
        $text = function ($t) {
            return is_array($t) ? $t[1] : $t;
        };
        $count = count($tokens);
        $found = 0;
        for ($i = 0; $i < $count && $found < count($anchor); $i++) {
            if ($text($tokens[$i]) === $anchor[$found]) {
                $found++;
            }
        }
        if ($found < count($anchor) || $text($tokens[$i]) !== '[') {
            throw new RuntimeException('no array after ' . implode(' ', $anchor) . " in $file");
        }
        $keys = [];
        $depth = 0;
        for (; $i < $count; $i++) {
            $t = $text($tokens[$i]);
            if ($t === '[' || $t === '(') {
                $depth++;
            } elseif ($t === ']' || $t === ')') {
                if (--$depth === 0) {
                    return $keys;
                }
            } elseif ($depth === 1 && is_array($tokens[$i]) && $tokens[$i][0] === T_CONSTANT_ENCAPSED_STRING
                && $text($tokens[$i + 1]) === '=>') {
                $keys[] = substr($t, 1, -1);
            }
        }
        throw new RuntimeException("unclosed array in $file");
    }

    /**
     * The literal value of a class constant, from the file declaring it.
     */
    private static function readConstant($file, $name)
    {
        $tokens = token_get_all(file_get_contents($file));
        $count = count($tokens);
        for ($i = 0; $i < $count; $i++) {
            if (!is_array($tokens[$i]) || $tokens[$i][0] !== T_CONST) {
                continue;
            }
            $j = $i + 1;
            while (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                $j++;
            }
            if (!is_array($tokens[$j]) || $tokens[$j][1] !== $name) {
                continue;
            }
            while ($tokens[$j] !== '=') {
                $j++;
            }
            $expression = '';
            $depth = 0;
            for ($j++; $j < $count; $j++) {
                $token = $tokens[$j];
                if ($token === ';' && $depth === 0) {
                    return eval("return $expression;");
                }
                if ($token === '[' || $token === '(') {
                    $depth++;
                } elseif ($token === ']' || $token === ')') {
                    $depth--;
                }
                $expression .= is_array($token) ? $token[1] : $token;
            }
        }
        throw new RuntimeException("$name not found in $file");
    }
}
