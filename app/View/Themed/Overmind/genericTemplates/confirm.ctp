<?php
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'model' => null,
    'url' => $this->request->here(false),
    'hiddenField' => false,
    'title' => $title ?? __('Are you sure?'),
    'message' => $question ?? '',
    'submitLabel' => $actionName ?? __('Confirm'),
    'submitIcon' => 'check',
]);
