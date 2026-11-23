<?php
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLCompiler.php';
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLRows.php';

/**
 * Shared by the MispQL tests. The models' REST_SEARCH_ORDER_FIELDS are read
 * from their source rather than by loading the classes: other tests declare
 * stand-ins for model classes (MispAttribute) in the same PHPUnit process.
 */
class MispQLFixtures
{
    /** @var array */
    private static $orderFields = [];

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
