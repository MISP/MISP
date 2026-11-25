<?php
App::uses('FormHelper', 'View/Helper');
App::uses('ColumnLimits', 'Tools');

/**
 * FormHelper that gives every text field the length of the column it posts to.
 *
 * Core FormHelper only does this from input(), and only for VARCHAR (describe()
 * gives TEXT columns no length); most templates call text() and textarea()
 * directly. AppModel refuses an overlong value on save whatever the form does —
 * this only stops the user typing or pasting it in the first place.
 */
class MispFormHelper extends FormHelper
{
    const TEXT_TYPES = ['text', 'email', 'url', 'search', 'tel'];

    public function __call($method, $params)
    {
        $type = $params[1]['type'] ?? $method;
        if (!empty($params) && in_array($type, self::TEXT_TYPES, true)) {
            $params[1] = $this->withColumnLimit($params[0], $params[1] ?? []);
        }
        return parent::__call($method, $params);
    }

    public function textarea($fieldName, $options = array())
    {
        return parent::textarea($fieldName, $this->withColumnLimit($fieldName, $options));
    }

    private function withColumnLimit($fieldName, array $options)
    {
        if (array_key_exists('maxlength', $options)) {
            return $options;
        }
        try {
            $this->setEntity($fieldName);
            $Model = $this->_getModel($this->model());
            $limit = $Model ? (ColumnLimits::of($Model)[$this->field()] ?? null) : null;
        } catch (Exception $e) {
            $limit = null;
        }
        if ($limit) {
            // maxlength counts characters; a byte limit is checked again on save.
            $options['maxlength'] = $limit['limit'];
        }
        return $options;
    }
}
