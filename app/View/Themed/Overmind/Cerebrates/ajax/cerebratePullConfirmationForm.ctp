<?php
$message = $question;

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => $title,
    'model' => 'Cerebrate',
    'url' => $baseurl . '/cerebrates/' . $this->view . '/' . $id,
    'message' => $message
]);
?>