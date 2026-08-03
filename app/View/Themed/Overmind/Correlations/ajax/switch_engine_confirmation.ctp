<?php
echo $this->element('genericElementsBS5/Forms/confirmationForm', array(
    'title' => __('Switch correlation engine'),
    'model' => 'Correlation',
    'url' => $baseurl . '/correlations/switchEngine/' . urlencode($engine),
    'hiddenField' => false,
    'message' => __('Make "%s" the engine every new correlation is written to?', $engine),
    'warning' => __('Correlations created while another engine was active are not carried over. Recorrelating afterwards is strongly recommended.'),
    'submitLabel' => __('Switch engine'),
    'submitIcon' => 'toggle-on',
));
