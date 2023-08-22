<?php
    if (is_array($fieldData)) {
        // Don't barf if the model is not explicitly passed
        $modelForForm = empty($data['model']) ?
            h(\Cake\Utility\Inflector::singularize(\Cake\Utility\Inflector::classify($this->request->getParam('controller')))) :
            h($data['model']);
        $fieldTemplate = 'genericField';
        if (!empty($fieldData['type'])) {
            if (file_exists(ROOT . '/templates/element/genericElements/Form/Fields/' . $fieldData['type'] . 'Field.php')) {
                $fieldTemplate = $fieldData['type'] . 'Field';
            }
        }
        if (empty($fieldData['label'])) {
            if (!isset($fieldData['label']) || $fieldData['label'] !== false) {
                $fieldData['label'] = \Cake\Utility\Inflector::humanize($fieldData['field']);
            }
        }
        $fieldDescription = $fieldData['tooltip'] ?? ($fieldDesc[$fieldData['field']] ?? false);
        if (!empty($fieldDescription)) {
            $fieldData['tooltip'] = $this->element(
                'genericElements/Form/formInfo', array(
                    'field' => $fieldData,
                    'fieldDesc' => $fieldDescription,
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
        if (empty($fieldData['type']) || ($fieldData['type'] !== 'checkbox' && $fieldData['type'] !== 'radio')) {
            $params['class'] .= ' form-control';
        }
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
        if (!empty($fieldData['div'])) {
            $temp = $this->Bootstrap->node('div', $fieldData['div'], $temp);
        }
        echo $temp;
    } else {
        echo $fieldData;
    }
