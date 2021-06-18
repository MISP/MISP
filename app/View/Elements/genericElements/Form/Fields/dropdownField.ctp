<?php
    $controlParams = [
        'options' => $fieldData['options'],
        'class' => ($fieldData['class'] ?? '') . ' formDropdown custom-select'
    ];
    echo $this->FormFieldMassage->prepareFormElement($this->Form, $controlParams, $fieldData);
