<?php
    $params['div'] = false;
    $params['class'] .= ' form-control';
    $params['value'] = '';
    echo $this->FormFieldMassage->prepareFormElement($this->Form, $params, $fieldData);
?>
