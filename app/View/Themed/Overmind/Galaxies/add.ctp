<?php
$isEdit = (($action ?? 'add') === 'edit');

$formUrl = $isEdit
    ? $baseurl . '/galaxies/edit/' . h($id)
    : $baseurl . '/galaxies/add';

$currentDist = $this->request->data['Galaxy']['distribution']
    ?? ($galaxy['Galaxy']['distribution'] ?? $initialDistribution);
$initDist = (int)$currentDist;

echo $this->Form->create('Galaxy', [
    'id' => 'galaxyAddForm',
    'url' => $formUrl,
    'novalidate' => true,
    // installRequiredFieldGuard() refuses a submit that leaves a `required`
    // field empty - the form is novalidate, so nothing else would.
    'data-required-guard' => '1',
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'galaxy',
    'eyebrow' => __('Galaxies'),
    'title' => $isEdit ? __('Edit Galaxy') : __('Add Custom Galaxy'),
    'icon' => 'misp-icon misp-icon-galaxy misp-simple',
]) ?>


<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4">

    <?php
    echo $this->Form->hidden('id');
    echo $this->Form->hidden('uuid');
    echo $this->Form->hidden('version');
    ?>

    <div class="row g-3">
        <!-- NAME -->
        <div class="col-md-7">
            <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->text('name', [
                'class' => 'form-control bg-light',
                'placeholder' => __('e.g. My custom threat actors'),
                'required' => true,
                'data-required-msg' => __('Please provide a name for the galaxy.'),
            ]) ?>
        </div>

        <!-- NAMESPACE -->
        <div class="col-md-5">
            <?= $this->Form->label('namespace', __('Namespace'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->text('namespace', [
                'class' => 'form-control bg-light',
                'placeholder' => __('e.g. custom'),
            ]) ?>
        </div>
    </div>

    <!-- DESCRIPTION -->
    <div class="mt-3">
        <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>
        <?= $this->Form->textarea('description', [
            'class' => 'form-control bg-light',
            'rows' => 2,
            'placeholder' => __('Briefly describe what this galaxy contains…'),
        ]) ?>
    </div>

    <!-- ICON -->
    <div class="mt-3">
        <?= $this->Form->label('icon', __('Icon'), ['class' => 'form-label fw-semibold']) ?>
        <div class="input-group">
            <span class="input-group-text bg-light"><i class="fas fa-icons"></i></span>
            <?= $this->Form->text('icon', [
                'class' => 'form-control bg-light',
                'placeholder' => __('FontAwesome icon name, e.g. user-secret'),
            ]) ?>
        </div>
        <div class="form-text">
            <?= __('Name of a FontAwesome icon (without the "fa-" prefix) used to represent this galaxy.') ?>
        </div>
    </div>

    <div class="mt-3">
        <?= $this->element('genericElementsBS5/Forms/distribution_field', [
            'accent' => 'galaxy',
            'id' => 'GalaxyDistribution',
            'value' => $initDist,
            'selectAttrs' => ['class' => 'Galaxy_distribution_select'],
        ]) ?>
    </div>

    <!-- KILL CHAIN ORDER (advanced) -->
    <div class="mt-3">
        <?= $this->element('genericElementsBS5/Forms/json_field', [
            'field' => 'kill_chain_order',
            'accent' => 'galaxy',
            'label' => __('Kill Chain order (for the Galaxy Matrix)'),
            'shape' => 'object',
            'rows' => 3,
            'minHeight' => '90px',
            'placeholder' => '{"fraud-tactics": ["Initiation", "Target Compromise"]}',
            'hint' => __('Optional — the kill-chain ordering a matrix galaxy is drawn in.'),
        ]) ?>
    </div>

    <!-- ENABLED -->
    <label class="galaxy-toggle-card d-flex align-items-center justify-content-between border rounded-3 p-3 mt-3 bg-light w-100"
           style="cursor:pointer;">
        <div class="d-flex align-items-center gap-3">
            <span class="d-inline-flex align-items-center justify-content-center rounded-circle flex-shrink-0"
                  style="width:2.25rem;height:2.25rem;background:rgba(139,92,246,.12);">
                <i class="fas fa-power-off text-galaxy"></i>
            </span>
            <div>
                <span class="fw-semibold d-block">
                    <?= __('Enabled') ?>
                </span>
                <span class="text-muted small">
                    <?= __('Make this galaxy available for tagging across the instance.') ?>
                </span>
            </div>
        </div>
        <div class="form-check form-switch form-switch-galaxy m-0 ps-0">
            <?php
            $enabledOpts = [
                'class' => 'form-check-input ms-0',
                'id' => 'GalaxyEnabled',
                'role' => 'switch',
                'hiddenField' => true,
                'style' => 'width:3rem;height:1.5rem;cursor:pointer;',
            ];
            if (!$isEdit) {
                $enabledOpts['checked'] = true;
            }
            echo $this->Form->checkbox('enabled', $enabledOpts);
            ?>
        </div>
    </label>

    <!-- ACTIONS -->
    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'galaxy',
        'isEdit' => $isEdit,
        'meta' => $isEdit ? [['label' => __('Galaxy'), 'id' => $id]] : [],
        'hint' => $isEdit ? '' : __('Clusters are added to the galaxy once it exists.'),
        'submit' => [
            'label' => $isEdit ? __('Save Changes') : __('Add Galaxy'),
            'icon' => 'fas fa-check',
        ],
    ]) ?>

</div>

<?= $this->Form->end(); ?>


