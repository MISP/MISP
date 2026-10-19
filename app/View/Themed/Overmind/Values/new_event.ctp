<?php
/**
 * The new event dialog of the value page: the value, and the enrichment
 * findings the reader picked. Laid out as Events/add is; the page's
 * value-new-event.js posts it to `createEvent` and stays on the page.
 *
 * @var array $dialog ValueNewEvent::forDialog()
 * @var string $valueB64
 */
$value = $dialog['value']['value'];
$shownValue = mb_strlen($value) > 80 ? mb_substr($value, 0, 79) . '…' : $value;
$currentThreatLevel = (int)(Configure::check('MISP.default_event_threat_level')
    ? Configure::read('MISP.default_event_threat_level')
    : 3);
$firstType = $dialog['value']['type'];
$typeInfo = $dialog['type_info'];

echo $this->Form->create('Event', [
    'id' => 'ValueNewEventForm',
    'url' => $baseurl . '/values/createEvent/' . $valueB64,
    'novalidate' => true,
    'data-vp-ne-form' => '1',
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'event',
    'eyebrow' => __('Value Intelligence'),
    'title' => sprintf(__('New event from %s'), $shownValue),
    'description' => sprintf(
        __('Creates an unpublished event owned by %s. Nothing leaves this instance until you publish it.'),
        $dialog['org']
    ),
    'icon' => 'misp-icon misp-icon-event misp-simple',
    'titleIcon' => 'fas fa-calendar-plus',
]) ?>

<script type="application/json" data-vp-ne-types><?= json_encode($typeInfo, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4 px-2">

        <div class="alert alert-danger d-none mb-0" role="alert" data-vp-ne-error></div>

        <?php if (!empty($dialog['missing'])): ?>
            <div class="alert alert-warning d-flex align-items-center gap-2 mb-0" role="status">
                <i class="fas fa-triangle-exclamation" aria-hidden="true"></i>
                <span><?= h(__n(
                    '%s picked finding is no longer in its module\'s answer and is left out.',
                    '%s picked findings are no longer in their module\'s answer and are left out.',
                    $dialog['missing'],
                    $dialog['missing']
                )) ?></span>
            </div>
        <?php endif; ?>

        <div class="w-100 ov-form-group">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Event Info'),
                'required' => true,
                'for' => 'ValueNewEventInfo',
            ]) ?>
            <?= $this->Form->textarea('info', [
                'class' => 'ov-form-line fs-5',
                'rows' => 2,
                'id' => 'ValueNewEventInfo',
                'value' => sprintf(__('%s — enrichment'), $value),
                'data-vp-ne-field' => 'info',
            ]) ?>
        </div>

        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                'value' => 0,
                'id' => 'ValueNewEventDistribution',
                'sgEmpty' => __('Select a sharing group…'),
            ]) ?>
        </div>

        <div class="row g-4 w-100 mx-0">
            <div class="col-md-6 ps-0">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'primary',
                    'label' => __('Analysis Level'),
                ]) ?>
                <?php
                $analysisMeta = [
                    0 => ['tone' => 'var(--misp-tone-blue-solid, #0d6efd)', 'sub' => __('Raw intelligence')],
                    1 => ['tone' => 'var(--misp-tone-orange-solid, #fd7e14)', 'sub' => __('Under investigation')],
                    2 => ['tone' => 'var(--misp-tone-green-solid, #198754)', 'sub' => __('Verified & closed')],
                ];
                $analysisOptions = [];
                foreach ($analysisLevels as $analysisId => $analysisName) {
                    $analysisOptions[] = ($analysisMeta[$analysisId] ?? [
                        'tone' => 'var(--misp-tone-gray-solid, #6c757d)',
                    ]) + ['value' => $analysisId, 'title' => $analysisName];
                }
                ?>
                <?= $this->element('genericElementsBS5/Forms/choice_slider', [
                    'field' => 'analysis',
                    'id' => 'ValueNewEventAnalysis',
                    'value' => 0,
                    'ariaLabel' => __('Analysis level'),
                    'options' => $analysisOptions,
                ]) ?>
            </div>
            <div class="col-md-6">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'primary',
                    'label' => __('Threat Level'),
                ]) ?>
                <?php
                $threatMeta = [
                    4 => ['tone' => 'var(--misp-tone-gray-solid, #41464b)', 'sub' => __('No risk')],
                    3 => ['tone' => 'var(--misp-tone-yellow-solid, #ffc107)', 'sub' => __('Opportunistic')],
                    2 => ['tone' => 'var(--misp-tone-orange-solid, #fd7e14)', 'sub' => __('Targeted campaign')],
                    1 => ['tone' => 'var(--misp-tone-red-solid, #dc3545)', 'sub' => __('Active exploitation')],
                ];
                $threatOptions = [];
                foreach ($threatMeta as $threatId => $meta) {
                    if (isset($threatLevels[$threatId])) {
                        $threatOptions[] = $meta + ['value' => $threatId, 'title' => $threatLevels[$threatId]];
                    }
                }
                foreach ($threatLevels as $threatId => $threatName) {
                    if (!isset($threatMeta[$threatId])) {
                        $threatOptions[] = [
                            'value' => $threatId,
                            'title' => $threatName,
                            'tone' => 'var(--misp-tone-gray-solid, #6c757d)',
                        ];
                    }
                }
                ?>
                <?= $this->element('genericElementsBS5/Forms/choice_slider', [
                    'field' => 'threat_level_id',
                    'id' => 'ValueNewEventThreatLevel',
                    'value' => $currentThreatLevel,
                    'ariaLabel' => __('Threat level'),
                    'options' => $threatOptions,
                ]) ?>
            </div>
        </div>

        <div class="w-100 ov-form-group">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Event Date (UTC)'),
                'required' => true,
                'for' => 'ValueNewEventDateDisplay',
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/date_field', [
                'field' => 'date',
                'id' => 'ValueNewEventDate',
                'value' => date('Y-m-d'),
                'required' => true,
                'requiredMsg' => __('Enter the event date.'),
                'invalidMsg' => __('Enter the event date as DD/MM/YYYY.'),
            ]) ?>
        </div>

        <div class="w-100 vp-ne-block">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'attribute',
                'label' => __('The value'),
            ]) ?>
            <div class="vp-ne-valuebox font-monospace" title="<?= h($value) ?>"><?= h($value) ?></div>
            <div class="row g-3 mt-0">
                <div class="col-sm-6 col-lg-4">
                    <label class="vp-ne-label" for="ValueNewEventType"><?= h(__('Type')) ?></label>
                    <select class="form-select font-monospace" id="ValueNewEventType"
                            name="data[Value][type]" data-vp-ne-type-for="#ValueNewEventCategory">
                        <?php foreach ($dialog['value']['types'] as $type): ?>
                            <option value="<?= h($type['type']) ?>"<?= $type['type'] === $firstType ? ' selected' : '' ?>><?= h($type['type']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-sm-6 col-lg-4">
                    <label class="vp-ne-label" for="ValueNewEventCategory"><?= h(__('Category')) ?></label>
                    <select class="form-select" id="ValueNewEventCategory" name="data[Value][category]">
                        <?php foreach ($typeInfo[$firstType]['categories'] as $category): ?>
                            <option value="<?= h($category) ?>"><?= h($category) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-12 col-lg-4">
                    <span class="vp-ne-label d-none d-lg-block" aria-hidden="true">&nbsp;</span>
                    <label class="vp-ne-ids">
                        <input type="hidden" name="data[Value][to_ids]" value="0">
                        <input type="checkbox" class="form-check-input" name="data[Value][to_ids]" value="1"
                               data-vp-ne-ids-for="#ValueNewEventType"<?= $typeInfo[$firstType]['to_ids'] ? ' checked' : '' ?>>
                        <span>
                            <span class="vp-ne-ids-title"><?= h(__('For IDS')) ?></span>
                            <span class="vp-ne-ids-sub"><?= h(__('Send to Intrusion Detection System')) ?></span>
                        </span>
                        <i class="fas fa-shield-halved" aria-hidden="true"></i>
                    </label>
                </div>
                <div class="col-12">
                    <label class="vp-ne-label" for="ValueNewEventComment"><?= h(__('Comment')) ?></label>
                    <input type="text" class="form-control" id="ValueNewEventComment" name="data[Value][comment]">
                </div>
            </div>
        </div>

        <div class="w-100 vp-ne-block" data-vp-ne-findings>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'object',
                'label' => __('Picked findings'),
                'badge' => $dialog['count'] ? (string)$dialog['count'] : '',
            ]) ?>
            <div class="vp-ne-empty<?= $dialog['count'] ? ' d-none' : '' ?>" data-vp-ne-empty>
                <i class="fas fa-circle-info" aria-hidden="true"></i>
                <span><?= h(__('Nothing picked — the event will hold only the value. Pick findings in the Enrichment tab to add them.')) ?></span>
            </div>
            <?php $i = 0; ?>
            <?php foreach ($dialog['groups'] as $group): ?>
                <div class="vp-ne-group" data-vp-ne-group>
                    <div class="vp-ne-group-head">
                        <i class="fas fa-wand-magic-sparkles" aria-hidden="true"></i>
                        <span class="font-monospace"><?= h($group['module']) ?></span>
                    </div>
                    <ul class="vp-ne-list">
                        <?php foreach ($group['findings'] as $finding): ?>
                            <?php $name = 'data[Finding][' . $i++ . ']'; ?>
                            <li class="vp-ne-f vp-ne-f-<?= h($finding['kind']) ?>" data-vp-ne-row="<?= h($finding['fp']) ?>">
                                <input type="hidden" name="<?= $name ?>[fp]" value="<?= h($finding['fp']) ?>">
                                <input type="hidden" name="<?= $name ?>[module]" value="<?= h($finding['module']) ?>">
                                <input type="hidden" name="<?= $name ?>[type]" value="<?= h($finding['type']) ?>">
                                <?php if ($finding['kind'] === 'object'): ?>
                                    <div class="vp-ne-f-main">
                                        <div class="vp-ne-f-line">
                                            <span class="misp-icon misp-icon-object misp-hexagone vp-ne-f-icon" aria-hidden="true"></span>
                                            <span class="vp-ne-f-name"><?= h($finding['name']) ?></span>
                                            <?php if ($finding['meta_category'] !== ''): ?>
                                                <span class="vp-ne-f-muted"><?= h($finding['meta_category']) ?></span>
                                            <?php endif; ?>
                                            <span class="vp-ne-f-count"><?= h(sprintf(
                                                __n('%d attribute', '%d attributes', $finding['attribute_count']),
                                                $finding['attribute_count']
                                            )) ?></span>
                                        </div>
                                        <div class="vp-ne-peeks">
                                            <?php foreach ($finding['peek'] as $peek): ?>
                                                <span class="vp-ne-peek<?= mb_strlen($peek) > 24 ? ' vp-ne-peek-long' : '' ?>" title="<?= h($peek) ?>"><?= h($peek) ?></span>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                    <div class="vp-ne-f-ctl">
                                        <label class="vp-ne-label" for="<?= h('ValueNewEventRel' . $i) ?>"><?= h(__('Linked to the value as')) ?></label>
                                        <input type="text" class="form-control form-control-sm font-monospace"
                                               id="<?= h('ValueNewEventRel' . $i) ?>" name="<?= $name ?>[relationship]"
                                               list="vp-ne-relationships" value="<?= h(ValueNewEventTool::DEFAULT_RELATIONSHIP) ?>" maxlength="191">
                                    </div>
                                <?php else: ?>
                                    <div class="vp-ne-f-main">
                                        <div class="vp-ne-f-line">
                                            <?php if (count($finding['types']) > 1): ?>
                                                <select class="form-select form-select-sm font-monospace vp-ne-f-type"
                                                        name="<?= $name ?>[attribute_type]"
                                                        aria-label="<?= h(__('Type')) ?>"
                                                        data-vp-ne-type-for="#<?= h('ValueNewEventCat' . $i) ?>">
                                                    <?php foreach ($finding['types'] as $type): ?>
                                                        <option value="<?= h($type) ?>"><?= h($type) ?></option>
                                                    <?php endforeach; ?>
                                                </select>
                                            <?php else: ?>
                                                <span class="vp-ne-type"><?= h($finding['attribute_type']) ?></span>
                                                <input type="hidden" name="<?= $name ?>[attribute_type]" value="<?= h($finding['attribute_type']) ?>">
                                            <?php endif; ?>
                                            <span class="vp-ne-f-val font-monospace" title="<?= h($finding['value']) ?>"><?= h($finding['value']) ?></span>
                                        </div>
                                    </div>
                                    <div class="vp-ne-f-ctl vp-ne-f-ctl-attr">
                                        <div>
                                            <label class="vp-ne-label" for="<?= h('ValueNewEventCat' . $i) ?>"><?= h(__('Category')) ?></label>
                                            <select class="form-select form-select-sm" id="<?= h('ValueNewEventCat' . $i) ?>" name="<?= $name ?>[category]">
                                                <?php foreach ($finding['categories'] as $category): ?>
                                                    <option value="<?= h($category) ?>"<?= $category === $finding['category'] ? ' selected' : '' ?>><?= h($category) ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <label class="vp-ne-f-ids">
                                            <span class="vp-ne-label"><?= h(__('IDS')) ?></span>
                                            <input type="hidden" name="<?= $name ?>[to_ids]" value="0">
                                            <span class="form-check form-switch m-0">
                                                <input type="checkbox" class="form-check-input" role="switch" name="<?= $name ?>[to_ids]" value="1"<?= $finding['to_ids'] ? ' checked' : '' ?>>
                                            </span>
                                        </label>
                                    </div>
                                <?php endif; ?>
                                <button type="button" class="btn btn-sm vp-ne-rm" data-vp-ne-rm="<?= h($finding['fp']) ?>"
                                        title="<?= h(__('Remove from the event')) ?>">
                                    <i class="fas fa-xmark" aria-hidden="true"></i>
                                    <span class="visually-hidden"><?= h(__('Remove from the event')) ?></span>
                                </button>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endforeach; ?>
            <datalist id="vp-ne-relationships">
                <?php foreach ($dialog['relationships'] as $relationship): ?>
                    <option value="<?= h($relationship) ?>"></option>
                <?php endforeach; ?>
            </datalist>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'event',
        'meta' => [['label' => __('Org'), 'value' => $dialog['org']]],
        'submit' => [
            'label' => __('Create event'),
            'icon' => 'fas fa-circle-plus',
            'id' => 'ValueNewEventSubmit',
            'class' => 'btn-primary',
            'type' => 'submit',
        ],
    ]) ?>

</div>

<?= $this->Form->end() ?>
