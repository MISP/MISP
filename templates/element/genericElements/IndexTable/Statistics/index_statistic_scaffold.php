<?php

$statisticsHtml = '';
if (!empty($statistics['created'])) {
    $statisticsHtml .= $this->element('genericElements/IndexTable/Statistics/index_statistic_timestamp', [
        'timeline' => $statistics,
    ]);
}
if (!empty($statistics['usage'])) {
    $statisticsHtml .= $this->element('genericElements/IndexTable/Statistics/index_statistic_field_amount', [
        'statistics' => $statistics,
    ]);
}
$statisticsHtml = sprintf('<div class="container-fluid"><div class="row gx-2">%s</div></div>', $statisticsHtml);
echo sprintf('<div class="index-statistic-container">%s</div>', $statisticsHtml);
?>
