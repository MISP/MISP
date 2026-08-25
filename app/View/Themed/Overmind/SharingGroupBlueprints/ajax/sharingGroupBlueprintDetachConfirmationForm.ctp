<?php
$message = $question;

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => $title,
    'model' => 'SharingGroupBlueprint',
    'url' => $baseurl . '/SharingGroupBlueprints/' . $this->view . '/' . $id,
    'message' => $message
]);
?>