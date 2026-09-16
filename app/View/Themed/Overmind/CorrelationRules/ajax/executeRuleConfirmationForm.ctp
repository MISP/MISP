<?php
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => $title,
    'model' => 'CorrelationRule',
    'url' => $baseurl . '/correlationRules/executeRule/' . $id,
    'message' => $question,
    'submitLabel' => __('Execute'),
    'submitIcon' => 'play',
]);
?>
