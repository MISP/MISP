<?php
/*
 * The value page's History tab (AuditLogsController::valueHistory): the audit
 * log's filter bar, then the value's history grouped by occurrence
 * (Values/View/value_history_body). The bar's filters narrow the entries the
 * history reads; the body pages its own sections.
 */
$history = $valueIntelligence['history'];

$what = __('What');
$who = __('Who');
$filterFields = [
    [
        'name' => 'model_title', 'label' => __('Title contains'), 'type' => 'text',
        'placeholder' => __('e.g. an event title or an object name'), 'group' => $what,
    ],
    [
        'name' => 'action', 'label' => __('Action'), 'type' => 'select',
        'options' => ['' => __('All actions')] + ($actions ?? []), 'group' => $what,
    ],
    [
        'name' => 'model', 'label' => __('Model'), 'type' => 'select',
        'options' => ['' => __('All models')] + array_combine($models ?? [], $models ?? []), 'group' => $what,
    ],
    [
        'name' => 'model_id', 'label' => __('Model ID'), 'type' => 'number',
        'placeholder' => __('e.g. 42'), 'group' => $what,
    ],
    [
        'name' => 'user', 'label' => __('User'), 'type' => 'text',
        'placeholder' => __('ID, e-mail or SYSTEM'), 'group' => $who,
        'requirement' => !empty($isSiteAdmin),
    ],
    [
        'name' => 'org', 'label' => __('Organisation'), 'type' => 'text',
        'placeholder' => __('ID, UUID or name'), 'group' => $who,
    ],
    [
        'name' => 'request_type', 'label' => __('Request type'), 'type' => 'select',
        'options' => ['' => __('Any'), 0 => __('Browser'), 1 => __('API'), 2 => __('CLI / background job')],
        'group' => $who,
    ],
    [
        'name' => 'created', 'label' => __('Created'), 'type' => 'date', 'group' => __('When'),
        // The entries by day, drawn as a strip with a brush across the bar.
        'histogram' => $valueIntelligence['history_strip'] ?? null,
        'note' => __('The strip in the bar keeps a period; here, presets and exact dates.'),
    ],
];

// The entries drawn, for the count beside the chips.
$rows = $history['event_entries'] ?? [];
foreach ($history['groups'] ?? [] as $group) {
    $rows = array_merge($rows, $group['entries']);
}
?>
<div class="container-fluid px-0" data-ifp-scope="<?= h('/audit_logs/valueHistory/' . $valueB64) ?>">

    <?php if (!empty($history['recorded'])): ?>
        <?= $this->element('Logs/filter_bar', [
            'item_url' => '/audit_logs',
            'action' => 'valueHistory',
            'search' => ['placeholder' => !empty($isSiteAdmin)
                ? __('Search title, model, action, user, org…')
                : __('Search title, model, action, org…')],
            'fields' => $filterFields,
            'rows' => $rows,
            'skip_pagination' => true,
        ]) ?>
    <?php endif; ?>

    <div class="index-results" data-ifp-results>
        <?= $this->element('Values/View/value_history_body', [
            'history' => $history,
            'filtered' => !empty($this->request->query) || !empty($quickFilter),
        ]) ?>
    </div>

</div>
