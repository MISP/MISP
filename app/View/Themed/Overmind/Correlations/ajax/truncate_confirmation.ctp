<?php
echo $this->element('genericElementsBS5/Forms/confirmationForm', array(
    'title' => __('Truncate the correlation table'),
    'model' => 'Correlation',
    'url' => $baseurl . '/correlations/truncate/' . urlencode($engine),
    'hiddenField' => false,
    'message' => __('Empty "%s", the table of the dormant "%s" engine?', $table_name, $engine),
    'warning' => __('Every correlation stored for that engine is dropped. Should you activate it again, the instance has to be recorrelated from scratch.'),
    'submitLabel' => __('Truncate'),
    'submitClass' => 'btn btn-danger',
    'submitIcon' => 'eraser',
));
