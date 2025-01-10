<?php
    $params['div'] = false;
    if (empty($fieldData['type']) || ($fieldData['type'] !== 'checkbox' && $fieldData['type'] !== 'radio')) {
        $params['class'] .= ' form-control';
    }
    echo $this->FormFieldMassage->prepareFormElement($this->Form, $params, $fieldData);
