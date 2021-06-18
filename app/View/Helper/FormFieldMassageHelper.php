<?php
App::uses('AppHelper', 'View/Helper');

class FormFieldMassageHelper extends AppHelper
{
    public function prepareFormElement(FormHelper $form, array $controlParams, array $fieldData)
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
