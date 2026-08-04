<?php

/**
 * Substitutes the four allowed variable forms in a template's
 * `info_template` string to produce the Event.info value at
 * instantiation time (PRD §7.1):
 *
 *   {{date}}         -> Y-m-d of event creation (override via $context['date'])
 *   {{now}}          -> ISO-8601 timestamp    (override via $context['now'])
 *   {{user}}         -> the creating user's email ($context['user'])
 *   {{field:<id>}}   -> first value of the user-submitted input for <id>;
 *                       empty string if unset.
 *
 * Unknown or malformed {{...}} sequences pass through unchanged —
 * EventTemplateValidator rejects them at save time, so by the time
 * we render we can trust the grammar.
 */
class EventTemplateInfoRenderer
{
    /**
     * @param string $template    info_template string from the template definition
     * @param array  $fieldValues map: element id -> value (string|null) or array of
     *                            values for repeatable fields (first is used)
     * @param array  $context     'user' => email, optional 'date' / 'now' overrides
     * @return string
     */
    public function render($template, array $fieldValues = array(), array $context = array())
    {
        if (!is_string($template) || $template === '') {
            return '';
        }
        return preg_replace_callback(
            '/\{\{(date|now|user|field:([a-zA-Z_][a-zA-Z0-9_]*))\}\}/',
            function ($m) use ($fieldValues, $context) {
                $expr = $m[1];
                if ($expr === 'date') {
                    return isset($context['date']) ? (string)$context['date'] : date('Y-m-d');
                }
                if ($expr === 'now') {
                    return isset($context['now']) ? (string)$context['now'] : date('c');
                }
                if ($expr === 'user') {
                    return isset($context['user']) ? (string)$context['user'] : '';
                }
                // {{field:<id>}}
                if (isset($m[2])) {
                    $id = $m[2];
                    if (!array_key_exists($id, $fieldValues)) {
                        return '';
                    }
                    $val = $fieldValues[$id];
                    if ($val === null) {
                        return '';
                    }
                    if (is_array($val)) {
                        return isset($val[0]) ? (string)$val[0] : '';
                    }
                    return (string)$val;
                }
                return $m[0];
            },
            $template
        );
    }
}
