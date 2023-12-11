<?php

/**
 * Behavior to trim all string fields in a model
 *
 * @author noud
 *
 */
class TrimBehavior extends ModelBehavior
{
    public function beforeValidate(Model $Model, $options = array())
    {
        foreach ($Model->data[$Model->name] as $key => $field) {
            if ($key !== 'data' && $key !== 'data_raw' && is_string($field)) {
                $Model->data[$Model->name][$key] = trim($field);
            }
        }
        return true;
    }
}
