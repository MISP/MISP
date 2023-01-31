<?php

namespace App\View\Helper;

use Cake\View\Helper;

class FormFieldMassageHelper extends Helper
{
    public function prepareFormElement(\Cake\View\Helper\FormHelper $form, array $controlParams, array $fieldData): string
    {
        if (!empty($fieldData['stateDependence'])) {
            $controlParams['data-dependence-source'] = h($fieldData['stateDependence']['source']);
            $controlParams['data-dependence-option'] = h($fieldData['stateDependence']['option']);
        }
        $controlParams['id'] = $fieldData['field'] . '-field';
        if (!empty($fieldData['autocomplete'])) {
            $controlParams['autocomplete'] = $fieldData['autocomplete'];
        }
        $formFieldElement = $form->control($fieldData['field'], $controlParams);
        if (!empty($fieldData['hidden'])) {
            $formFieldElement = '<span class="hidden">' . $formFieldElement . '</span>';
        }
        return $formFieldElement;
    }
}
