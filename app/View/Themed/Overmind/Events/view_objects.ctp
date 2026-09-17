<?php
$paginatorUrl = [
    'controller' => 'events',
    'action'     => 'viewObjects',
    $event['Event']['id'],
];
if (!empty($extended)) {
    $paginatorUrl['extended'] = 1;
}
if (!empty($extending)) {
    $paginatorUrl['extending'] = 1;
}
foreach (($this->request->params['named'] ?? []) as $namedKey => $namedValue) {
    if ($namedKey !== 'page') {
        $paginatorUrl[$namedKey] = $namedValue;
    }
}
$this->Paginator->options(['url' => $paginatorUrl]);

echo $this->element('Objects/index', [
    'objects' => $objects,
    'show_event_id' => false
]);
