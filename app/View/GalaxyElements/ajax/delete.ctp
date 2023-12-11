<?php
    echo $this->element('/genericElements/Form/hardSoftDeleteForm', [
        'title' => __('Delete Galaxy Cluster Element'),
        'modelName' => __('galaxy element'),
        'value' => $element['GalaxyElement']['key'] . ' :: ' . $element['GalaxyElement']['value'],
        'id' => $element['GalaxyElement']['id'],
        'hardDeleteURL' => sprintf('%s/galaxy_elements/delete/%s/1', $baseurl, $element['GalaxyElement']['id']),
        'doNotShowHelp' => true
    ]);
?>
