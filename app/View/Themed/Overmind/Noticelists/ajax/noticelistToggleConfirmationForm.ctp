
<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to %s %s noticelist ?', h($actionText), count($idArray))
    : __('Are you sure you want to %s noticelist #%s ?', h($actionText), h($idArray[0]));

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Noticelist Toggle'),
    'model' => 'Noticelist',
    'url' => $url,
    'message' => $message
]);
?>