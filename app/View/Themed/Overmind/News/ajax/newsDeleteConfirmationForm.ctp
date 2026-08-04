<?php
$message = count($idArray) > 1
    ? __('Are you sure you want to delete %s news items ?', count($idArray))
    : __('Are you sure you want to delete news item #%s ?', $idArray[0]);

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('News Deletion'),
    'model' => 'News',
    'url' => $baseurl . '/news/deleteSelection',
    'message' => $message
]);
?>
