<?php
// Posts back to the URL that served it: download_* carries two ids, pull_* one.
echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => $title,
    'model' => 'Cerebrate',
    'url' => $this->request->here(),
    'hiddenField' => false,
    'message' => $question,
    'submitLabel' => $actionName ?? __('Pull'),
    'submitIcon' => 'circle-arrow-down',
]);
?>
