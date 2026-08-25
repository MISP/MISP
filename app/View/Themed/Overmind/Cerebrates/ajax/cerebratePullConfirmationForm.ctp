<?php
$message = $question;

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title' => $title,
    'model' => 'Cerebrate',
    'url' => $baseurl . '/cerebrates/' . $this->view . '/' . $id,
    'message' => $message
]);
?>