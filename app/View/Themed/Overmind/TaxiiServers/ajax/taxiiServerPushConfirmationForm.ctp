<?php

echo $this->element('genericElementsBS5/Modals/confirmation_form', [
    'title' => $title,
    'model' => 'TaxiiServer',
    'url' => $baseurl . '/taxiiServers/push/' . $id,
    'message' => $question,
    'submitLabel' => __('Push'),
    'submitIcon' => 'paper-plane',
]);
?>