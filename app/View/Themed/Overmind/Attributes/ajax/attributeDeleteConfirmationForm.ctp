<?php
if (count($idArray) > 1) {
    $hard_message = __('Are you sure you want to hard-delete Attribute #%s?', count($idArray));
    $soft_message = __('Are you sure you want to soft-delete Attribute #%s?', count($idArray));
} else {
    $hard_message = __('Are you sure you want to hard-delete Attribute #%s?', h($id));
    $soft_message = __('Are you sure you want to soft-delete Attribute #%s?', h($id));
}

echo $this->element('genericElementsBS5/Forms/deleteConfirmationForm', [
    'title' => __('Attribute Deletion'),
    'model' => 'Attribute',
    'url' => $baseurl . '/attributes/delete/' . $id . ($hard ? '/true' : ''),
    'message' => $hard ? $hard_message : $soft_message
]);
?>