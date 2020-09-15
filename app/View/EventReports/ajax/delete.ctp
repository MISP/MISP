<?php
    echo $this->element('/genericElements/Form/hardSoftDeleteForm', [
        'title' => __('Delete Event Report'),
        'modelName' => __('report'),
        'value' => $report['name'],
        'id' => $report['id'],
        'softDeleteURL' => sprintf('%s/eventReports/delete/%s', $baseurl, $report['id']),
        'hardDeleteURL' => sprintf('%s/eventReports/delete/%s/1', $baseurl, $report['id']),
    ]);
?>
