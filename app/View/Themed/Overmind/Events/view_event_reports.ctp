<?php
$paginatorUrl = [
    'controller' => 'events',
    'action'     => 'viewEventReports',
    $event['Event']['id'],
];
if (!empty($extended)) {
    $paginatorUrl['extended'] = 1;
}
if (!empty($extending)) {
    $paginatorUrl['extending'] = 1;
}
$this->Paginator->options(['url' => $paginatorUrl]);
?>

<?php echo $this->element('EventReports/index', [
    'reports' => $reports,
    'eventView' => true,
]); ?>
