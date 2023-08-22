<?php
    $params['class'] .= ' form-check-input';
    $params['templates'] = [
        'nestingLabel' => '{{hidden}}{{input}}<label class="form-check-label" {{attrs}}>{{text}}</label>{{tooltip}}',
        'inputContainer' => '<div class="form-check">{{content}}</div>'
    ];
    echo $this->FormFieldMassage->prepareFormElement($this->Form, $params, $fieldData);
?>
