<?php

App::uses('Regexp', 'Model');

/**
 * Behavior to regexp all string fields in a model
 */
class RegexpBehavior extends ModelBehavior
{
    private $__allRegexp = null;

    const EXCLUDED_TYPES = ['sigma', 'size-in-bytes', 'counter', 'float'];

    /**
     * replace the current value according to the regexp rules, or block blocklisted regular expressions
     *
     * @param Model $Model
     * @param string $type
     * @param string $value
     * @return string
     */
    public function runRegexp(Model $Model, $type, $value)
    {
        if (in_array($type, self::EXCLUDED_TYPES, true)) {
            return $value;
        }

        if ($this->__allRegexp === null) {
            $regexp = new Regexp();
            $this->__allRegexp = array_column($regexp->find('all', [
                'order' => 'id ASC',
                'fields' => ['type', 'regexp', 'replacement'],
            ]), 'Regexp');
        }

        foreach ($this->__allRegexp as $regexp) {
            if ($regexp['type'] === 'ALL' || $regexp['type'] === $type) {
                if (!empty($regexp['replacement']) && !empty($regexp['regexp'])) {
                    $value = preg_replace($regexp['regexp'], $regexp['replacement'], $value);
                }
                if (empty($regexp['replacement']) && preg_match($regexp['regexp'], $value)) {
                    return false;
                }
            }
        }
        return $value;
    }
}
