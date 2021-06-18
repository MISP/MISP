<?php
    if (is_array($fieldData)) {
        if (empty($fieldData['type'])) {
            $fieldData['type'] = 'text';
        }
        $fieldTemplate = 'genericField';
        if (file_exists(ROOT . '/app/View/Elements/genericElements/Form/Fields/' . $fieldData['type'] . 'Field.ctp')) {
            $fieldTemplate = $fieldData['type'] . 'Field';
        }
        if (empty($fieldData['label'])) {
            $fieldData['label'] = Inflector::humanize($fieldData['field']);
        }
        if (!empty($fieldDesc[$fieldData['field']])) {
            $fieldData['label'] .= $this->element(
                'genericElements/Form/formInfo', array(
                    'field' => $fieldData,
                    'fieldDesc' => $fieldDesc[$fieldData['field']],
                    'modelForForm' => $modelForForm
                )
            );
        }
        $params = array();
        if (!empty($fieldData['class'])) {
            if (is_array($fieldData['class'])) {
                $class = implode(' ', $fieldData['class']);
            } else {
                $class = $fieldData['class'];
            }
            $params['class'] = $class;
        } else {
            $params['class'] = '';
        }
        if (empty($fieldData['type']) || $fieldData['type'] !== 'checkbox' ) {
            $params['class'] .= ' form-control';
        }
        //$params['class'] = sprintf('form-control %s', $params['class']);
        foreach ($fieldData as $k => $fd) {
            if (!isset($simpleFieldWhitelist) || in_array($k, $simpleFieldWhitelist) || strpos($k, 'data-') === 0) {
                $params[$k] = $fd;
            }
        }
        $temp = $this->element('genericElements/Form/Fields/' . $fieldTemplate, array(
            'fieldData' => $fieldData,
            'params' => $params
        ));
        if (!empty($fieldData['hidden'])) {
            $temp = '<span class="hidden">' . $temp . '</span>';
        }
        echo $temp;
        // $fieldsArrayForPersistence []= $modelForForm . \Cake\Utility\Inflector::camelize($fieldData['field']);
    } else {
        echo $fieldData;
    }
