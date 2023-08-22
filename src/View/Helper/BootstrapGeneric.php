<?php

namespace App\View\Helper;

use Cake\Utility\Text;
use InvalidArgumentException;

class BootstrapGeneric
{
    public static $variants = ['primary', 'secondary', 'success', 'danger', 'warning', 'info', 'light', 'dark', 'white', 'transparent'];
    public static $textClassByVariants = [
        'primary' => 'text-light',
        'secondary' => 'text-light',
        'success' => 'text-light',
        'danger' => 'text-light',
        'warning' => 'text-dark',
        'info' => 'text-light',
        'light' => 'text-dark',
        'dark' => 'text-light',
        'white' => 'text-dark',
        'transparent' => 'text-dark'
    ];
    protected $allowedOptionValues = [];
    protected $options = [];

    protected function checkOptionValidity()
    {
        foreach ($this->allowedOptionValues as $option => $values) {
            if (!isset($this->options[$option])) {
                throw new InvalidArgumentException(__('Option `{0}` should have a value', $option));
            }
            if (!in_array($this->options[$option], $values)) {
                throw new InvalidArgumentException(__('Option `{0}` is not a valid option for `{1}`. Accepted values: {2}', json_encode($this->options[$option]), $option, json_encode($values)));
            }
        }
    }

    /**
     * Replaces {{placeholders}} inside a $template with the given $data
     * 
     * Example:
     * ```
     * render('{{name}} is {{age}} years old.', ['name' => 'Bob', 'age' => '65']);
     * ```
     * Returns: Bob is 65 years old.
     *
     * @param string $template The template containing the placeholders
     * @param array $data A K-V array where keys are placeholder name to be replaced by their value
     * @param array<string, mixed> $options Array of options passed to the Text::insert function
     * @return string
     */
    public static function render(string $template, array $data, array $options = []): string
    {
        $defaults = [
            'before' => '{{', 'after' => '}}', 'escape' => '\\', 'format' => null, 'clean' => false,
        ];
        $options += $defaults;
        return Text::insert(
            $template,
            $data,
            $options
        );
    }

    /**
     * Creates an HTML node
     *
     * # Options
     *
     * - `escape` Set to false to disable escaping of attribute value.
     * 
     * @param string $tag The tag of the node. Example: 'div', 'span'
     * @param array $attrs Attributes to be added to the node
     * @param string|array<string> $content Optional content to be added as innerHTML. If an array is given, it gets converted into string
     * @param array $options Array of options
     * @return string
     */
    public static function node(string $tag, array $attrs = [], $content = '', array $options = []): string
    {
        return self::render(
            '<{{tag}} {{attrs}}>{{content}}</{{tag}}>',
            [
                'tag' => $tag,
                'attrs' => self::buildAttrs($attrs, $options),
                'content' => is_array($content) ? implode('', $content) : $content,
            ]
        );
    }

    public static function nodeOpen(string $tag, array $attrs = [], array $options = []): string
    {
        return self::render(
            '<{{tag}} {{attrs}}>',
            [
                'tag' => $tag,
                'attrs' => self::buildAttrs($attrs, $options),
            ]
        );
    }

    public static function nodeClose(string $tag): string
    {
        return self::render(
            '</{{tag}}>',
            [
                'tag' => $tag,
            ]
        );
    }

    /**
     * Build a space-delimited string with each HTML attribute generated.
     *
     * @param array $attrs
     * @param array<string, mixed> $options Array of options
     * @return string
     */
    public static function buildAttrs(array $attrs, array $options): string
    {
        $defaults = [
            'escape' => true,
        ];
        $options = $options + $defaults;

        $attributes = [];
        foreach ($attrs as $key => $value) {
            if (!empty($key) && $value !== null) {
                $attributes[] = self::__formatAttribute((string) $key, $value, $options['escape']);
            }
        }
        $html = trim(implode(' ', $attributes));
        return $html;
    }

    /**
     * Format an individual HTML attribute
     * Support minimized attributes such as `selected` and `disabled`
     *
     * @param string $key The name of the attribute
     * @param array<string>|string $value The value of the attribute
     * @param bool $escape Should the attribute value be escaped
     * @return string
     */
    public static function __formatAttribute(string $key, $value, bool $escape = true): string
    {
        $value = is_array($value) ? implode(' ', $value) : $value;
        if (is_numeric($key)) {
            return sprintf('%s="%s"', h($value), (!empty($escape) ? h($value) : $value));
        }
        $isMinimized = isset(COMPACT_ATTRIBUTES[$key]);
        if ($isMinimized) {
            if (!empty($value)) {
                return sprintf('%s="%s"', h($key), (!empty($escape) ? h($value) : $value));
            }
            return '';
        } else if (!isset($value)) {
            return '';
        }
        return sprintf('%s="%s"', h($key), (!empty($escape) ? h($value) : $value));
    }

    protected static function genHTMLParams($params)
    {
        $html = '';
        foreach ($params as $k => $v) {
            if (!empty($k) && (isset($v) && $v !== '')) {
                $html .= BootstrapGeneric::genHTMLParam($k, $v) . ' ';
            }
        }
        return $html;
    }

    protected static function genHTMLParam($paramName, $values)
    {
        if (!is_array($values)) {
            $values = [$values];
        }
        return sprintf('%s="%s"', $paramName, implode(' ', $values));
    }

    protected static function convertToArrayIfNeeded($data): array
    {
        return is_array($data) ? $data : [$data];
    }

    protected static function genericCloseButton($dismissTarget)
    {
        return self::node('button', [
            'type' => 'button',
            'class' => 'btn-close',
            'data-bs-dismiss' => $dismissTarget,
            'arial-label' => __('Close')
        ]);
    }

    protected static function getTextClassForVariant(string $variant): string
    {
        return !empty(self::$textClassByVariants[$variant]) ? self::$textClassByVariants[$variant] : 'text-black';
    }

    protected static function getBGAndTextClassForVariant(string $variant): string
    {
        return sprintf('bg-%s %s', $variant, self::getTextClassForVariant($variant));
    }
}
