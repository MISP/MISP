<?php
$isEdit = (($action ?? 'add') === 'edit');

$formUrl = $isEdit
    ? $baseurl . '/galaxies/edit/' . h($id)
    : $baseurl . '/galaxies/add';

$currentDist = $this->request->data['Galaxy']['distribution']
    ?? ($galaxy['Galaxy']['distribution'] ?? $initialDistribution);
$initDist = (int)$currentDist;

// Only the levels $distributionLevels offers are rendered — the loop below
// drives the cards and looks the presentation up here by level.
$distIconMap = $this->DistributionLevel->all();

echo $this->Form->create('Galaxy', [
    'id' => 'galaxyAddForm',
    'url' => $formUrl,
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(139,92,246,.06);
            border-bottom:2px solid var(--bs-galaxy);">
    <div>
        <div class="text-galaxy text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Galaxies') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-circle-plus text-galaxy" style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Galaxy') : __('Add Custom Galaxy') ?>
        </h4>
    </div>
    <span class="misp-icon misp-icon-galaxy misp-simple text-galaxy"
          style="font-size:2rem; opacity:.5;"></span>
</div>


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

    <!-- DISTRIBUTION CARDS -->
    <div class="mt-3">
        <div class="text-galaxy fw-bold text-uppercase mb-2"
             style="font-size:.65rem; letter-spacing:.1em;">
            <?= __('Distribution') ?>
        </div>
        <?= $this->Form->select('distribution', $distributionLevels, [
            'id' => 'GalaxyDistribution',
            'class' => 'Galaxy_distribution_select',
            'value' => $initDist,
            'style' => 'display:none;',
        ]) ?>
        <div class="row g-2" id="galaxyDistCardRow">
            <?php foreach ($distributionLevels as $level => $label):
                $level = (int)$level;
                $ic = $distIconMap[$level]
                    ?? ['bg' => '#f1f1f1', 'color' => '#333', 'icon' => 'fas fa-question'];
                $sel = ($level === $initDist);
                $bdr = $sel
                    ? 'border-color:var(--bs-galaxy) !important;background:rgba(139,92,246,.08);'
                    : 'border-color:#d8dde3;';
            ?>
            <div class="col dist-card-col"
                 style="cursor:pointer;"
                 data-dist-value="<?= $level ?>">
                <div class="border rounded p-2 d-flex flex-column align-items-center gap-1 h-100 text-center"
                     style="transition:border-color .15s,background .15s; <?= $bdr ?>">
                    <span class="d-inline-flex align-items-center justify-content-center rounded-circle mb-1"
                          style="width:1.8rem;height:1.8rem;
                                 background:<?= h($ic['bg']) ?>;
                                 border:1px solid <?= h($ic['color']) ?>30;">
                        <i class="<?= h($ic['icon']) ?>"
                           style="color:<?= h($ic['color']) ?>;font-size:.7rem;"></i>
                    </span>
                    <span class="fw-bold lh-sm"
                          style="font-size:.68rem;color:var(--bs-body-color);">
                        <?= h($label) ?>
                    </span>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- KILL CHAIN ORDER (advanced) -->
    <div class="mt-3">
        <?= $this->Form->label('kill_chain_order', __('Kill Chain order (for the Galaxy Matrix)'), ['class' => 'form-label fw-semibold']) ?>
        <?= $this->Form->textarea('kill_chain_order', [
            'class' => 'form-control font-monospace bg-light',
            'rows' => 3,
            'placeholder' => '{ "fraud-tactics": [ "Initiation", "Target Compromise", … ] }',
        ]) ?>
        <div class="form-text">
            <?= __('Optional JSON describing the kill-chain ordering for matrix galaxies.') ?>
        </div>
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
    <div class="d-flex justify-content-end gap-3 mt-4">
        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
            <?= __('Cancel') ?>
        </button>
        <button type="submit" class="btn btn-galaxy text-light">
            <i class="fas fa-check me-1"></i>
            <?= $isEdit ? __('Save changes') : __('Add galaxy') ?>
        </button>
    </div>

</div>

<?= $this->Form->end(); ?>

<script>
(function () {
    var distSel = document.getElementById('GalaxyDistribution');
    document.querySelectorAll('#galaxyDistCardRow .dist-card-col').forEach(function (card) {
        card.addEventListener('click', function () {
            document.querySelectorAll('#galaxyDistCardRow .dist-card-col > div').forEach(function (d) {
                d.style.borderColor = '#d8dde3';
                d.style.background = '';
            });
            var inner = card.querySelector('div');
            if (inner) {
                inner.style.borderColor = 'var(--bs-galaxy)';
                inner.style.background = 'rgba(139,92,246,.08)';
            }
            if (distSel) distSel.value = card.dataset.distValue;
        });
    });
})();
</script>
