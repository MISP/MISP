<?php
    // form-check-inline on the div
    $params['class'] .= ' form-check-input';
    $params['templates'] = [
        'nestingLabel' => '{{input}}<label class="form-check-label" {{attrs}}>{{text}}</label>',
        'radioWrapper' => sprintf('<div class="form-check %s">{{label}}</div>', !empty($fieldData['inline']) ? 'form-check-inline' : ''),
    ];
    unset($params['inline']);
    echo $this->FormFieldMassage->prepareFormElement($this->Form, $params, $fieldData);
?>
