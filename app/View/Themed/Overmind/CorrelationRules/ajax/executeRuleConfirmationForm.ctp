<?php
echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => $title,
    'model' => 'CorrelationRule',
    'url' => $baseurl . '/correlationRules/executeRule/' . $id,
    'message' => $question
]);
?>
