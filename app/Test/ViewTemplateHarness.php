<?php
/**
 * Renders a single .ctp template without booting CakePHP, for tests that
 * check what a template itself prints. Helpers and nested elements are stubs
 * that print nothing, so a nested element has to be rendered on its own.
 */

if (!function_exists('h')) {
    function h($text, $double = true, $charset = null)
    {
        return htmlspecialchars((string)$text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8', $double);
    }
}

if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        if ($args === null) {
            return $singular;
        }
        return vsprintf($singular, is_array($args) ? $args : array_slice(func_get_args(), 1));
    }
}

if (!function_exists('__n')) {
    function __n($singular, $plural, $count, ...$args)
    {
        return vsprintf($count == 1 ? $singular : $plural, $args ?: [$count]);
    }
}

if (!class_exists('Configure')) {
    class Configure
    {
        private static $values = array();

        public static function read($key = null)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }
    }
}

if (!class_exists('Inflector')) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Inflector.php';
}

/** What a stubbed helper returns: an empty string that can also be indexed. */
class ViewTemplateHarnessBlank implements ArrayAccess
{
    public function __toString()
    {
        return '';
    }

    public function offsetExists($offset): bool
    {
        return false;
    }

    #[\ReturnTypeWillChange]
    public function offsetGet($offset)
    {
        return '';
    }

    public function offsetSet($offset, $value): void
    {
    }

    public function offsetUnset($offset): void
    {
    }
}

class ViewTemplateHarnessHelper
{
    public function __call($name, $args)
    {
        return new ViewTemplateHarnessBlank();
    }
}

class ViewTemplateHarness
{
    const VIEW = __DIR__ . '/../View/';

    public function __get($name)
    {
        return new ViewTemplateHarnessHelper();
    }

    public function element($name, $data = array(), $options = array())
    {
        return '';
    }

    public function fetch($name)
    {
        return '';
    }

    /**
     * @param string $template path under app/View
     * @param array $vars the view variables
     * @return string
     */
    public function render($template, array $vars)
    {
        extract($vars);
        ob_start();
        try {
            include self::VIEW . $template;
        } finally {
            $html = ob_get_clean();
        }
        return $html;
    }
}
