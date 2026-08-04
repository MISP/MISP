<?php
    echo $this->element('/genericElements/Form/hardSoftDeleteForm', [
        'title' => __('Delete Event Report'),
        'modelName' => __('report'),
        'value' => $report['EventReport']['name'],
        'id' => $report['EventReport']['id'],
        'softDeleteURL' => sprintf('%s/eventReports/delete/%s', $baseurl, $report['EventReport']['id']),
        'hardDeleteURL' => sprintf('%s/eventReports/delete/%s/1', $baseurl, $report['EventReport']['id']),
    ]);
?>
