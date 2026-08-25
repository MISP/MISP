<?php
$message =  $question . $id;

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => $title,
    'model' => 'TaxiiServer',
    'url' => $baseurl . '/taxiiServers/push/' . $id,
    'message' => $message
]);
?>