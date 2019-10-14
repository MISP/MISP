<?php

App::uses('Regexp', 'Model');

/**
 * Behavior to regexp all string fields in a model
 */
class RegexpBehavior extends ModelBehavior
{
    private $__allRegexp = null;

    public $excluded_types = array('sigma', 'float');

    /**
     * replace the current value according to the regexp rules, or block blacklisted regular expressions
     *
     * @param Model $Model
     * @param string $type
     * @param string $value
     * @return string
     */
    public function runRegexp(Model $Model, $type, $value)
    {
        if (in_array($type, $this->excluded_types)) {
            return $value;
        }

        if ($this->__allRegexp === null) {
            $regexp = new Regexp();
            $this->__allRegexp = $regexp->find('all', array('order' => 'id ASC'));
        }

        foreach ($this->__allRegexp as $regexp) {
            if ($regexp['Regexp']['type'] === 'ALL' || $regexp['Regexp']['type'] === $type) {
                if (!empty($regexp['Regexp']['replacement']) && !empty($regexp['Regexp']['regexp'])) {
                    $value = preg_replace($regexp['Regexp']['regexp'], $regexp['Regexp']['replacement'], $value);
                }
                if (empty($regexp['Regexp']['replacement']) && preg_match($regexp['Regexp']['regexp'], $value)) {
                    return false;
                }
            }
        }
        return $value;
    }
}
