<?php
$message = $question;

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => $title,
    'model' => 'Cerebrate',
    'url' => $baseurl . '/cerebrates/' . $this->view . '/' . $id,
    'message' => $message,
    'submitLabel' => __('Pull'),
    'submitIcon' => 'circle-arrow-down',
]);
?>