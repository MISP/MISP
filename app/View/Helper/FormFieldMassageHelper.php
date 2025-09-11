<?php
App::uses('AppHelper', 'View/Helper');

class FormFieldMassageHelper extends AppHelper
{
    public function prepareFormElement(FormHelper $form, array $controlParams, array $fieldData): string
    {
        $label = '<label class="col-sm-2 col-form-label form-label">' . h($fieldData['label']) . '</label>';
        unset($fieldData['label']);
        if (!empty($fieldData['tooltip'])) {
            $controlParams['templateVars'] = array_merge(
                $controlParams['templateVars'] ?? [],
                ['tooltip' => $fieldData['tooltip'],]
            );
        }
        if (!empty($fieldData['stateDependence'])) {
            $controlParams['data-dependence-source'] = h($fieldData['stateDependence']['source']);
            $controlParams['data-dependence-option'] = h($fieldData['stateDependence']['option']);
        }
        $controlParams['id'] = $fieldData['field'] . '-field';
        if (!empty($fieldData['autocomplete'])) {
            $controlParams['autocomplete'] = $fieldData['autocomplete'];
        }
        if (!empty($fieldData['type']) && $fieldData['type'] === 'checkbox') {
            $formFieldElement = $form->input($fieldData['field'], $controlParams);
            $formFieldElement = sprintf(
                '<div class="">%s</div>',
                $formFieldElement
            );
        } else {
            $controlParams['label'] = false;
            $formFieldElement = $form->input($fieldData['field'], $controlParams);
            $formFieldElement = sprintf(
                '<div class="row mb-3">%s<div class="col-sm-10">%s</div></div>',
                $label,
                $formFieldElement
            );
        }
        if (!empty($fieldData['hidden'])) {
            $formFieldElement = '<span class="hidden">' . $formFieldElement . '</span>';
        }
        return $formFieldElement;
    }
}
