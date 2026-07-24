<?php
$isEdit = isset($action) && $action === 'edit';
$restrict = !empty($restrictEdition);
$data = $this->request->data['DecayingModel'] ?? [];
$params = $data['parameters'] ?? [];

$title = $isEdit ? __('Edit decaying model') : __('Add decaying model');

echo $this->Form->create('DecayingModel', [
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<div class="container-fluid px-0">
    <div class="card border-0">
        <div class="card-body">

            <h3 class="mb-1"><?= h($title) ?></h3>
            <div class="form-text mb-3">
                <?= __('A decaying model describes how the score of an indicator decreases over time. For visual, interactive tuning use the ') ?>
                <a href="<?= h($baseurl . '/decayingModel/decayingTool') ?>"><?= __('Decaying Tool') ?></a>.
            </div>

            <?php if ($restrict): ?>
                <div class="alert alert-warning d-flex align-items-center gap-2">
                    <i class="fas fa-lock"></i>
                    <?= __('This is a default model — only sharing and the enabled state can be changed.') ?>
                </div>

                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('all_orgs', ['class' => 'form-check-input', 'checked' => $data['all_orgs'] ?? true]) ?>
                    <label class="form-check-label" for="DecayingModelAllOrgs"><?= __('Usable by every organisation') ?></label>
                </div>
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('enabled', ['class' => 'form-check-input', 'checked' => !empty($data['enabled'])]) ?>
                    <label class="form-check-label" for="DecayingModelEnabled"><?= __('Enabled') ?></label>
                </div>

            <?php else: ?>

                <div class="row g-3">
                    <div class="col-md-8">
                        <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->text('name', ['class' => 'form-control', 'required' => true, 'value' => $data['name'] ?? '']) ?>
                    </div>
                    <div class="col-md-4">
                        <?= $this->Form->label('formula', __('Formula'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->select('formula', $available_formulas, [
                            'class' => 'form-select',
                            'empty' => false,
                            'value' => $data['formula'] ?? 'Polynomial',
                        ]) ?>
                    </div>
                    <div class="col-12">
                        <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->textarea('description', ['class' => 'form-control', 'rows' => 2, 'value' => $data['description'] ?? '']) ?>
                    </div>
                </div>

                <div class="d-flex flex-wrap gap-4 mt-3">
                    <div class="form-check form-switch">
                        <?= $this->Form->checkbox('all_orgs', ['class' => 'form-check-input', 'checked' => $data['all_orgs'] ?? true]) ?>
                        <label class="form-check-label" for="DecayingModelAllOrgs"><?= __('Usable by every organisation') ?></label>
                    </div>
                    <div class="form-check form-switch">
                        <?= $this->Form->checkbox('enabled', ['class' => 'form-check-input', 'checked' => !empty($data['enabled'])]) ?>
                        <label class="form-check-label" for="DecayingModelEnabled"><?= __('Enabled') ?></label>
                    </div>
                </div>

                <hr class="my-4">
                <h6 class="fw-semibold text-uppercase text-secondary mb-3" style="letter-spacing:.06em; font-size:.72rem;">
                    <?= __('Parameters') ?>
                </h6>

                <div class="row g-3">
                    <div class="col-6 col-md-3">
                        <?= $this->Form->label('DecayingModel.parameters.lifetime', __('Lifetime (days)'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->number('DecayingModel.parameters.lifetime', ['class' => 'form-control', 'min' => 0, 'value' => $params['lifetime'] ?? 30]) ?>
                        <div class="form-text"><?= __('Time after which the score reaches 0.') ?></div>
                    </div>
                    <div class="col-6 col-md-3">
                        <?= $this->Form->label('DecayingModel.parameters.decay_speed', __('Decay speed'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->number('DecayingModel.parameters.decay_speed', ['class' => 'form-control', 'min' => 0, 'step' => 0.01, 'value' => $params['decay_speed'] ?? 0.3]) ?>
                        <div class="form-text"><?= __('How fast the indicator loses score.') ?></div>
                    </div>
                    <div class="col-6 col-md-3">
                        <?= $this->Form->label('DecayingModel.parameters.threshold', __('Cutoff threshold'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->number('DecayingModel.parameters.threshold', ['class' => 'form-control', 'min' => 0, 'max' => 100, 'value' => $params['threshold'] ?? 30]) ?>
                        <div class="form-text"><?= __('Score at which it is marked decayed.') ?></div>
                    </div>
                    <div class="col-6 col-md-3">
                        <?= $this->Form->label('DecayingModel.parameters.default_base_score', __('Default base score'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->number('DecayingModel.parameters.default_base_score', ['class' => 'form-control', 'min' => 0, 'max' => 100, 'value' => $params['default_base_score'] ?? 0]) ?>
                        <div class="form-text"><?= __('Used when no tags drive the base score.') ?></div>
                    </div>
                </div>

                <div class="mt-3">
                    <button class="btn btn-sm btn-link px-0 text-decoration-none" type="button"
                            data-bs-toggle="collapse" data-bs-target="#dmAdvanced">
                        <i class="fas fa-sliders me-1"></i><?= __('Advanced JSON (base score config &amp; settings)') ?>
                    </button>
                    <div class="collapse" id="dmAdvanced">
                        <div class="row g-3 mt-0">
                            <div class="col-md-6">
                                <?= $this->Form->label('DecayingModel.parameters.base_score_config', __('Base score config (JSON)'), ['class' => 'form-label fw-semibold']) ?>
                                <?= $this->Form->textarea('DecayingModel.parameters.base_score_config', [
                                    'class' => 'form-control font-monospace',
                                    'rows' => 5,
                                    'value' => isset($params['base_score_config']) ? json_encode($params['base_score_config']) : '{}',
                                ]) ?>
                            </div>
                            <div class="col-md-6">
                                <?= $this->Form->label('DecayingModel.parameters.settings', __('Model settings (JSON)'), ['class' => 'form-label fw-semibold']) ?>
                                <?= $this->Form->textarea('DecayingModel.parameters.settings', [
                                    'class' => 'form-control font-monospace',
                                    'rows' => 5,
                                    'value' => isset($params['settings']) ? json_encode($params['settings']) : '{}',
                                ]) ?>
                            </div>
                        </div>
                    </div>
                </div>

            <?php endif; ?>

            <div class="d-flex justify-content-end gap-3 mt-4">
                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                    <?= __('Cancel') ?>
                </button>
                <?= $this->Form->button(
                    '<i class="fas fa-check me-1"></i> ' . ($isEdit ? __('Save changes') : __('Create model')),
                    ['class' => 'btn btn-primary', 'escapeTitle' => false]
                ) ?>
            </div>

        </div>
    </div>
</div>

<?= $this->Form->end(); ?>
