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
        if (!empty($fieldData['description'])) {
            if (!isset($params['class'])) {
                $params['class'] = '';
            }
            $params['class'] .= ' input-with-description';
        }
        if (!empty($fieldData['picker']) && isset($fieldData['picker']['function'])) {
            $fieldData['picker']['text'] = isset($fieldData['picker']['text']) ? $fieldData['picker']['text'] : __('Picker');
            $params['div'] = 'input text input-append';
            $params['after'] = sprintf('<button type="button" class="btn" onclick="%s.call(this);">%s</button>', $fieldData['picker']['function'], __($fieldData['picker']['text']));
        }
        //$params['class'] = sprintf('form-control %s', $params['class']);
        foreach ($fieldData as $k => $fd) {
            if (!isset($simpleFieldAllowlist) || in_array($k, $simpleFieldAllowlist) || strpos($k, 'data-') === 0) {
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
