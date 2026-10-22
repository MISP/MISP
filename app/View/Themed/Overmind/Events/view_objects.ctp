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
    if ($namedKey !== 'page' && $namedKey !== 'focus') {
        $paginatorUrl[$namedKey] = $namedValue;
    }
}
$this->Paginator->options(['url' => $paginatorUrl]);

echo $this->element('Objects/index', [
    'objects' => $objects,
    'show_event_id' => false
]);
echo $this->element('Events/View/list_focus', ['focusId' => $focusId ?? null]);
?>

<?php
// The tab badge counts the event's objects, so a filtered load leaves it alone.
$filterKeys = [
    'deleted', 'name', 'object', 'meta-category', 'searchFor', 'proposal', 'category', 'type', 'tags',
    'galaxy', 'org', 'toIDS', 'correlation', 'feed', 'warning', 'analystData', 'narrower', 'seen',
];
$filtered = array_intersect_key(
    array_filter($this->request->params['named'] ?? [], function ($value) {
        return is_array($value) ? !empty($value) : !in_array((string)$value, ['', '0'], true);
    }),
    array_flip($filterKeys)
);
?>
<?php if (empty($filtered)): ?>
<script>
if (typeof setTabCount === 'function') {
    setTabCount('objects', <?= (int)($total ?? 0) ?>);
}
</script>
<?php endif; ?>
