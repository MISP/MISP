<?php
/**
 * Add / Edit / Fork galaxy cluster modal (Overmind theme).
 *
 * Available vars: $galaxy_id, $distributionLevels (0-4), $initialDistribution,
 * $sharingGroups, $action, and in fork mode $forkedClusterMeta + prefilled
 * $this->request->data.
 */
$isEdit = (($action ?? 'add') === 'edit');
$isFork = !$isEdit && isset($forkedClusterMeta);
$currentDist = $this->request->data['GalaxyCluster']['distribution'] ?? $initialDistribution;
$initDist = (int)$currentDist;

// In edit mode the form must POST to edit()
$formUrl = $isEdit
    ? $baseurl . '/galaxy_clusters/edit/' . h($clusterId ?? $id ?? '')
    : $baseurl . '/galaxy_clusters/add/' . h($galaxy_id);

$distIconMap = $this->DistributionLevel->all();

echo $this->Form->create('GalaxyCluster', [
    'id' => 'galaxyClusterAddForm',
    'url' => $formUrl,
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(139,92,246,.06); border-bottom:2px solid var(--bs-galaxy);">
    <div>
        <div class="text-galaxy text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Galaxy Clusters') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : ($isFork ? 'code-branch' : 'circle-plus') ?> text-galaxy" style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Galaxy Cluster') : ($isFork ? __('Fork Galaxy Cluster') : __('Add Galaxy Cluster')) ?>
        </h4>
    </div>
    <span class="misp-icon misp-icon-galaxy misp-simple text-galaxy" style="font-size:2rem; opacity:.5;"></span>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4">

    <?php
    echo $this->Form->hidden('galaxy_id', ['value' => $galaxy_id]);
    echo $this->Form->hidden('extends_uuid');
    echo $this->Form->hidden('extends_version');
    if ($isEdit) {
        echo $this->Form->hidden('id');
        echo $this->Form->hidden('uuid');
    }
    ?>

    <?php if ($isFork): ?>
        <div class="alert alert-info d-flex gap-2 py-2">
            <i class="fas fa-code-branch mt-1"></i>
            <div class="small">
                <?= __('This cluster is forked from') ?>
                <strong><?= h($forkedClusterMeta['value'] ?? '') ?></strong>.
            </div>
        </div>
    <?php endif; ?>

    <!-- NAME -->
    <div class="mb-3">
        <?= $this->Form->label('value', __('Name'), ['class' => 'form-label fw-semibold']) ?>
        <?= $this->Form->text('value', [
            'class' => 'form-control bg-light',
            'placeholder' => __('The value / name of the cluster'),
            'required' => true,
        ]) ?>
    </div>

    <!-- DESCRIPTION -->
    <div class="mb-3">
        <?= $this->Form->label('description', __('Description'), ['class' => 'form-label fw-semibold']) ?>
        <?= $this->Form->textarea('description', [
            'class' => 'form-control bg-light',
            'rows' => 2,
            'placeholder' => __('Briefly describe this cluster…'),
        ]) ?>
    </div>

    <div class="row g-3">
        <!-- SOURCE -->
        <div class="col-md-6">
            <?= $this->Form->label('source', __('Source'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->text('source', [
                'class' => 'form-control bg-light',
                'placeholder' => __('e.g. the origin of this cluster'),
            ]) ?>
        </div>
        <!-- AUTHORS -->
        <div class="col-md-6">
            <?= $this->Form->label('authors', __('Authors'), ['class' => 'form-label fw-semibold']) ?>
            <?= $this->Form->text('authors', [
                'class' => 'form-control bg-light',
                'placeholder' => __('Comma separated or JSON array'),
            ]) ?>
        </div>
    </div>

    <!-- DISTRIBUTION CARDS -->
    <div class="mt-3">
        <div class="text-galaxy fw-bold text-uppercase mb-2" style="font-size:.65rem; letter-spacing:.1em;">
            <?= __('Distribution') ?>
        </div>
        <?= $this->Form->select('distribution', $distributionLevels, [
            'id' => 'ClusterDistribution',
            'value' => $initDist,
            'style' => 'display:none;',
        ]) ?>
        <div class="row g-2" id="clusterDistCardRow">
            <?php foreach ($distributionLevels as $level => $label):
                $level = (int)$level;
                $ic = $distIconMap[$level] ?? ['bg' => '#f1f1f1', 'color' => '#333', 'icon' => 'fas fa-question'];
                $sel = ($level === $initDist);
                $bdr = $sel
                    ? 'border-color:var(--bs-galaxy) !important;background:rgba(139,92,246,.08);'
                    : 'border-color:#d8dde3;';
            ?>
            <div class="col dist-card-col" style="cursor:pointer;" data-dist-value="<?= $level ?>">
                <div class="border rounded p-2 d-flex flex-column align-items-center gap-1 h-100 text-center"
                     style="transition:border-color .15s,background .15s; <?= $bdr ?>">
                    <span class="d-inline-flex align-items-center justify-content-center rounded-circle mb-1"
                          style="width:1.8rem;height:1.8rem;background:<?= h($ic['bg']) ?>;border:1px solid <?= h($ic['color']) ?>30;">
                        <i class="<?= h($ic['icon']) ?>" style="color:<?= h($ic['color']) ?>;font-size:.7rem;"></i>
                    </span>
                    <span class="fw-bold lh-sm" style="font-size:.68rem;color:var(--bs-body-color);"><?= h($label) ?></span>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>

    <!-- SHARING GROUP (shown only for distribution = 4) -->
    <div class="mt-3" id="clusterSGWrapper" style="<?= ($initDist === 4) ? '' : 'display:none;' ?>">
        <?= $this->Form->label('sharing_group_id', __('Sharing Group'), ['class' => 'form-label fw-semibold']) ?>
        <?= $this->Form->select('sharing_group_id', $sharingGroups, [
            'id' => 'ClusterSharingGroup',
            'class' => 'form-select bg-light',
            'empty' => __('Select a sharing group…'),
        ]) ?>
    </div>

    <!-- ELEMENTS -->
    <div class="mt-3">
        <?= $this->Form->label('elements', __('Galaxy Cluster Elements'), ['class' => 'form-label fw-semibold']) ?>
        <?= $this->Form->textarea('elements', [
            'class' => 'form-control font-monospace bg-light',
            'rows' => 5,
            'placeholder' => '[ { "key": "synonyms", "value": "..." } ]',
        ]) ?>
        <div class="form-text">
            <?= __('Valid JSON array of objects of the form {key: keyname, value: actualValue}.') ?>
        </div>
    </div>

    <!-- ACTIONS -->
    <div class="d-flex justify-content-end gap-3 mt-4">
        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
            <?= __('Cancel') ?>
        </button>
        <button type="submit" class="btn btn-galaxy text-light">
            <i class="fas fa-check me-1"></i>
            <?= $isEdit ? __('Save changes') : ($isFork ? __('Fork cluster') : __('Add cluster')) ?>
        </button>
    </div>

</div>

<?= $this->Form->end(); ?>

<script>
(function () {
    var distSel = document.getElementById('ClusterDistribution');
    var sgWrapper = document.getElementById('clusterSGWrapper');
    document.querySelectorAll('#clusterDistCardRow .dist-card-col').forEach(function (card) {
        card.addEventListener('click', function () {
            document.querySelectorAll('#clusterDistCardRow .dist-card-col > div').forEach(function (d) {
                d.style.borderColor = '#d8dde3';
                d.style.background = '';
            });
            var inner = card.querySelector('div');
            if (inner) {
                inner.style.borderColor = 'var(--bs-galaxy)';
                inner.style.background = 'rgba(139,92,246,.08)';
            }
            var val = card.dataset.distValue;
            if (distSel) distSel.value = val;
            if (sgWrapper) sgWrapper.style.display = (val == 4) ? '' : 'none';
        });
    });
})();
</script>
