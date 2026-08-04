<?php
echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => $title,
    'model' => 'CorrelationRule',
    'url' => $baseurl . '/correlationRules/executeRule/' . $id,
    'message' => $question
]);
?>
