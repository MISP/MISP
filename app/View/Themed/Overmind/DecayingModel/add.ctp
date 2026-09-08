<?php
$isEdit = isset($action) && $action === 'edit';
/* A default model ships with MISP: only its sharing and enabled state may move. */
$restrict = !empty($restrictEdition);
$data = $this->request->data['DecayingModel'] ?? [];
$params = $data['parameters'] ?? [];

/* The four numeric parameters of the decay curve, so the grid below stays one
 * loop rather than four near-identical blocks. */
$curveParams = [
    [
        'field' => 'lifetime',
        'label' => __('Lifetime (days)'),
        'hint' => __('Time after which the score reaches 0.'),
        'default' => 30,
        'attrs' => ['min' => 0],
    ],
    [
        'field' => 'decay_speed',
        'label' => __('Decay speed'),
        'hint' => __('How fast the indicator loses score.'),
        'default' => 0.3,
        'attrs' => ['min' => 0, 'step' => 0.01],
    ],
    [
        'field' => 'threshold',
        'label' => __('Cutoff threshold'),
        'hint' => __('Score at which it is marked decayed.'),
        'default' => 30,
        'attrs' => ['min' => 0, 'max' => 100],
    ],
    [
        'field' => 'default_base_score',
        'label' => __('Default base score'),
        'hint' => __('Used when no tags drive the base score.'),
        'default' => 0,
        'attrs' => ['min' => 0, 'max' => 100],
    ],
];

echo $this->Form->create('DecayingModel', [
    'id' => 'decayingModelForm',
    'novalidate' => true,
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Decaying Models'),
    'title' => $isEdit ? __('Edit Decaying Model') : __('Add Decaying Model'),
    'description' => __('A decaying model describes how the score of an indicator decreases over time.'),
    'icon' => 'fas fa-hourglass-half',
    'isEdit' => $isEdit,
]);
?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <?php if ($restrict): ?>

            <div class="alert alert-warning d-flex align-items-center gap-2 mb-0">
                <i class="fas fa-lock"></i>
                <?= __('This is a default model — only sharing and the enabled state can be changed.') ?>
            </div>

        <?php else: ?>

            <!-- ── IDENTITY ────────────────────────────────────── -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Name'),
                    'required' => true,
                ]) ?>
                <?= $this->Form->text('name', [
                    'id' => 'DecayingModelName',
                    'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                    'style' => 'border-bottom:1px solid #d8dde3 !important; outline:none;',
                    'placeholder' => __('e.g. Fast-decaying phishing URLs'),
                    'autocomplete' => 'off',
                    'required' => true,
                    'value' => $data['name'] ?? '',
                ]) ?>
            </div>

            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Description'),
                ]) ?>
                <?= $this->Form->textarea('description', [
                    'id' => 'DecayingModelDescription',
                    'class' => 'form-control',
                    'style' => 'border-color:#d8dde3;',
                    'rows' => 2,
                    'placeholder' => __('What this model is meant for'),
                    'value' => $data['description'] ?? '',
                ]) ?>
            </div>

            <!-- ── CURVE ───────────────────────────────────────── -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Decay curve'),
                ]) ?>
                <div class="row g-3">
                    <div class="col-12 col-md-4">
                        <label class="form-label text-muted mb-1" for="DecayingModelFormula"
                               style="font-size:.75rem;">
                            <i class="fas fa-square-root-variable me-1" style="font-size:.7rem;"></i>
                            <?= __('Formula') ?>
                        </label>
                        <?= $this->Form->select('formula', $available_formulas, [
                            'id' => 'DecayingModelFormula',
                            'class' => 'form-select tom-select',
                            'empty' => false,
                            'value' => $data['formula'] ?? 'Polynomial',
                        ]) ?>
                    </div>
                    <?php foreach ($curveParams as $param): ?>
                        <div class="col-6 col-md-2">
                            <?php $inputId = 'DecayingModelParameters' . Inflector::camelize($param['field']); ?>
                            <label class="form-label text-muted mb-1" for="<?= h($inputId) ?>"
                                   style="font-size:.75rem;">
                                <?= h($param['label']) ?>
                            </label>
                            <?= $this->Form->number(
                                'DecayingModel.parameters.' . $param['field'],
                                $param['attrs'] + [
                                    'id' => $inputId,
                                    'class' => 'form-control',
                                    'style' => 'border-color:#d8dde3;',
                                    'value' => $params[$param['field']] ?? $param['default'],
                                ]
                            ) ?>
                            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                                'text' => $param['hint'],
                                'icon' => '',
                            ]) ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- ── ADVANCED ────────────────────────────────────── -->
            <div class="w-100 px-2">
                <button class="btn btn-sm btn-link px-0 text-decoration-none" type="button"
                        data-bs-toggle="collapse" data-bs-target="#dmAdvanced">
                    <i class="fas fa-sliders me-1"></i>
                    <?= __('Advanced JSON (base score config & settings)') ?>
                </button>
                <div class="collapse" id="dmAdvanced">
                    <div class="row g-3 mt-0">
                        <?php
                        $advanced = [
                            'base_score_config' => __('Base score config (JSON)'),
                            'settings' => __('Model settings (JSON)'),
                        ];
                        foreach ($advanced as $field => $label):
                            $inputId = 'DecayingModelParameters' . Inflector::camelize($field);
                        ?>
                            <div class="col-md-6">
                                <label class="form-label text-muted mb-1" for="<?= h($inputId) ?>"
                                       style="font-size:.75rem;">
                                    <?= h($label) ?>
                                </label>
                                <?= $this->Form->textarea(
                                    'DecayingModel.parameters.' . $field,
                                    [
                                        'id' => $inputId,
                                        'class' => 'form-control font-monospace',
                                        'style' => 'border-color:#d8dde3; resize:vertical;',
                                        'rows' => 5,
                                        'spellcheck' => 'false',
                                        'value' => isset($params[$field])
                                            ? json_encode($params[$field])
                                            : '{}',
                                    ]
                                ) ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

        <?php endif; ?>

        <!-- ── SHARING ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Sharing'),
            ]) ?>
            <div class="d-flex flex-wrap gap-4">
                <div class="form-check form-switch">
                    <?= $this->Form->checkbox('all_orgs', [
                        'class' => 'form-check-input',
                        'id' => 'DecayingModelAllOrgs',
                        'checked' => $data['all_orgs'] ?? true,
                    ]) ?>
                    <label class="form-check-label" for="DecayingModelAllOrgs">
                        <?= __('Usable by every organisation') ?>
                    </label>
                </div>
                <div class="form-check form-switch">
                    <?= $this->Form->checkbox('enabled', [
                        'class' => 'form-check-input',
                        'id' => 'DecayingModelEnabled',
                        'checked' => !empty($data['enabled']),
                    ]) ?>
                    <label class="form-check-label" for="DecayingModelEnabled">
                        <?= __('Enabled') ?>
                    </label>
                </div>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($id) ? [['label' => __('Model'), 'id' => $id]] : [],
        'hint' => __('Scores are recomputed the next time an attribute is read, not on save.'),
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Create Model')],
    ]) ?>

</div>

<?= $this->Form->end() ?>
