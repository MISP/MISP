<?php
echo $this->element('genericElementsBS5/Forms/confirmationForm', array(
    'title' => __('Recorrelate the instance'),
    'model' => 'MISPAttribute',
    'url' => $baseurl . '/attributes/generateCorrelation',
    'hiddenField' => false,
    'size' => 'md',
    'message' => __('Rebuild every correlation of the currently active engine?'),
    'warning' => __('Depending on the size of the instance this can run for a long time. It is queued as a background job you can follow in Administration → Jobs.'),
    'submitLabel' => __('Recorrelate'),
    'submitIcon' => 'rotate',
));
