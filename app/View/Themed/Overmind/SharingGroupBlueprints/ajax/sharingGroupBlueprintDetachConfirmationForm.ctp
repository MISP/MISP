<?php
$message = $question;

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => $title,
    'model' => 'SharingGroupBlueprint',
    'url' => $baseurl . '/SharingGroupBlueprints/' . $this->view . '/' . $id,
    'message' => $message
]);
?>