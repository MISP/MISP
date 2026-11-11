<?php
/*
 * Identity and capabilities of a workflow module or trigger.
 *
 * The hues follow the indexes: violet modules, magenta logic, teal triggers,
 * amber ad-hoc workflows.
 */
$MODULE_TYPE_HUE = [
    'action' => 258,
    'logic' => 322,
    'trigger' => 174,
    'adhoc' => 38,
];

$type = $data['module_type'] ?? '';
$isTrigger = $type === 'trigger';
$isAdhoc = !empty($data['is_adhoc']);
$palette = $this->GalaxyColour->paletteFromHue($MODULE_TYPE_HUE[$isAdhoc ? 'adhoc' : $type] ?? 210);

$typeLabels = [
    'action' => __('Action module'),
    'logic' => __('Logic module'),
    'trigger' => $isAdhoc ? __('Ad-hoc trigger') : __('Trigger'),
];

$triggerOverhead = [
    1 => ['class' => 'success', 'text' => __('low')],
    2 => ['class' => 'warning', 'text' => __('medium')],
    3 => ['class' => 'danger', 'text' => __('high')],
];

$flag = function ($on, $yes = null, $no = null) {
    return $this->element('genericElementsBS5/Badges/boolean', [
        'boolean' => !empty($on),
        'full' => true,
        'true' => $yes ?? __('Yes'),
        'false' => $no ?? __('No'),
        'trueColor' => 'success',
        'falseColor' => 'secondary',
        'trueIcon' => 'fa-check',
        'falseIcon' => 'fa-xmark',
    ]);
};

$tiles = [
    [
        'label' => __('Status'),
        'html' => $this->element('genericElementsBS5/Badges/boolean', [
            'boolean' => empty($data['disabled']),
            'full' => true,
            'true' => __('Enabled'),
            'false' => __('Disabled'),
            'trueColor' => 'success',
            'falseColor' => 'danger',
            'trueIcon' => 'fa-check-circle',
            'falseIcon' => 'fa-times-circle',
        ]),
    ],
    [
        'label' => __('Blocking'),
        'html' => $flag($data['blocking'] ?? false),
        'hint' => $isTrigger
            ? __('A blocking trigger can stop the operation that fired it.')
            : __('A blocking module can stop the workflow it runs in.'),
    ],
];
if ($isTrigger) {
    $tiles[] = [
        'label' => __('Sends core format'),
        'html' => $flag($data['misp_core_format'] ?? false),
        'hint' => __('The data passed to the workflow is in MISP core format.'),
    ];
    if (!$isAdhoc && !empty($data['scope'])) {
        $tiles[] = [
            'label' => __('Scope'),
            'html' => sprintf('<span class="badge rounded-pill fw-normal ov-wf-chip">%s</span>', h($data['scope'])),
        ];
    }
    $level = $data['trigger_overhead'] ?? null;
    if (!$isAdhoc && !empty($triggerOverhead[$level])) {
        $tiles[] = [
            'label' => __('Overhead'),
            'html' => sprintf(
                '<span class="badge rounded-pill text-bg-%s">%s</span>',
                $triggerOverhead[$level]['class'],
                h($triggerOverhead[$level]['text'])
            ),
            'hint' => $data['trigger_overhead_message'] ?? '',
        ];
    }
} else {
    $tiles[] = [
        'label' => __('Expects core format'),
        'html' => $flag($data['expect_misp_core_format'] ?? false),
        'hint' => __('The module reads its input in MISP core format.'),
    ];
    $tiles[] = [
        'label' => __('misp-module'),
        'html' => $flag($data['is_misp_module'] ?? false),
    ];
    $tiles[] = [
        'label' => __('Custom'),
        'html' => $flag($data['is_custom'] ?? false),
    ];
    $tiles[] = [
        'label' => __('Filtering'),
        'html' => $flag($data['support_filters'] ?? false),
        'hint' => __('The module can narrow the data it acts on with a filter.'),
    ];
    $tiles[] = [
        'label' => __('Connectors'),
        'html' => sprintf(
            '<span class="small"><i class="fas fa-right-to-bracket text-muted me-1"></i>%s'
                . '<i class="fas fa-right-from-bracket text-muted ms-3 me-1"></i>%s</span>',
            h(__n('%s input', '%s inputs', (int)($data['inputs'] ?? 0), (int)($data['inputs'] ?? 0))),
            h(__n('%s output', '%s outputs', (int)($data['outputs'] ?? 0), (int)($data['outputs'] ?? 0)))
        ),
    ];
}

$filters = $data['trigger_filters'] ?? null;
?>

<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <div class="d-flex align-items-start gap-3 mb-4">
            <span class="d-inline-flex align-items-center justify-content-center rounded-3 shadow-sm flex-shrink-0"
                  style="width:3.25rem;height:3.25rem;font-size:1.4rem;background:<?= $palette['tintBg'] ?>;color:<?= $palette['tintIcon'] ?>;">
                <?php if (!empty($data['icon'])): ?>
                    <i class="<?= h($this->FontAwesome->getClass($data['icon'])) ?>"></i>
                <?php elseif (!empty($data['icon_path'])): ?>
                    <img src="<?= h($baseurl . '/img/' . $data['icon_path']) ?>"
                         alt="<?= h(__('Icon of %s', $data['name'])) ?>"
                         style="width:1.6rem;height:1.6rem;object-fit:contain;">
                <?php else: ?>
                    <i class="fas fa-cube"></i>
                <?php endif; ?>
            </span>
            <div class="flex-grow-1 overflow-hidden">
                <div class="d-flex align-items-center flex-wrap gap-2">
                    <span class="fw-semibold fs-5"><?= h($data['name']) ?></span>
                    <span class="badge rounded-pill"
                          style="background:<?= $palette['tintBg'] ?>;color:<?= $palette['tintIcon'] ?>;">
                        <?= h($typeLabels[$type] ?? $type) ?>
                    </span>
                    <?php if (!empty($data['version'])): ?>
                        <?php // Badges/version casts to int, which turns 0.4 into v0 ?>
                        <span class="badge bg-primary-subtle text-primary fw-semibold">v<?= h($data['version']) ?></span>
                    <?php endif; ?>
                </div>
                <div class="d-flex align-items-center gap-2 mt-1">
                    <code class="small text-body-secondary"><?= h($data['id']) ?></code>
                    <button type="button" class="btn btn-sm btn-link p-0 text-muted"
                            title="<?= h(__('Copy the module ID')) ?>"
                            onclick='copyValueToClipboard(<?= h(json_encode((string)$data['id'])) ?>, <?= h(json_encode(__('Module ID copied'))) ?>)'>
                        <i class="far fa-copy"></i>
                    </button>
                </div>
            </div>
        </div>

        <?php if (!empty($data['description'])): ?>
            <div class="mb-4">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Description') ?></div>
                <div class="bg-body-tertiary border rounded p-3"><?= nl2br(h($data['description'])) ?></div>
            </div>
        <?php endif; ?>

        <div class="row g-3">
            <?php foreach ($tiles as $tile): ?>
                <div class="col-sm-6 col-xl-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1">
                        <?= h($tile['label']) ?>
                        <?php if (!empty($tile['hint'])): ?>
                            <i class="fas fa-circle-question ms-1 opacity-75" title="<?= h($tile['hint']) ?>"></i>
                        <?php endif; ?>
                    </div>
                    <div><?= $tile['html'] ?></div>
                </div>
            <?php endforeach; ?>
        </div>

        <?php if ($isAdhoc): ?>
            <hr class="my-4 opacity-25">
            <div class="row g-3">
                <div class="col-md-4">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Data input') ?></div>
                    <?php if (!empty($data['trigger_scope'])): ?>
                        <span class="badge rounded-pill fw-normal ov-wf-chip"><?= h($data['trigger_scope']) ?></span>
                    <?php else: ?>
                        <span class="text-muted small fst-italic"><?= __('not configured') ?></span>
                    <?php endif; ?>
                </div>
                <div class="col-md-8">
                    <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Search filters') ?></div>
                    <?php if (!empty($filters)): ?>
                        <?= $this->element('genericElementsBS5/Badges/json', ['json' => $filters, 'full' => true]) ?>
                    <?php else: ?>
                        <span class="text-muted small">&ndash;</span>
                    <?php endif; ?>
                </div>
            </div>
            <div class="form-text mt-2">
                <?= __('Both are set on the trigger node of the workflow, in the editor.') ?>
            </div>
        <?php endif; ?>

    </div>
</div>

