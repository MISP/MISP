<?php
$message =  $question . $id;

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => $title,
    'model' => 'TaxiiServer',
    'url' => $baseurl . '/taxiiServers/push/' . $id,
    'message' => $message
]);
?>