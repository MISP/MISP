<?php
$message = $question;

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => $title,
    'model' => 'SharingGroupBlueprint',
    'url' => $baseurl . '/SharingGroupBlueprints/' . $this->view . '/' . $id,
    'message' => $message,
    'accent' => 'warning',
    'submitLabel' => __('Detach'),
    'submitIcon' => 'link-slash',
]);
?>