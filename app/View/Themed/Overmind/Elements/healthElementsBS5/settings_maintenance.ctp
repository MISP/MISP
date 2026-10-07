<?php
/**
 * Maintenance tools: consistency checks run on demand and the clean-up
 * routines. The checks and confirmations are wired by server-settings.js
 * (data-dg-check, dgConfirm), the clean-ups are plain postLinks.
 */

$uid = 'dg' . dechex(mt_rand());
$confirmations = array();
?>
<div class="dg-scope" id="<?= h($uid) ?>">
<?php
$confirmations[$uid . '-cache'] = array(
    'title' => __('Clean the model cache'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Rebuilds the cached database schema. Safe to run whenever fields or tables look to be missing.')) . '</p>',
    'label' => __('Clean cache'), 'cls' => 'btn-primary',
);
$confirmations[$uid . '-authkeys'] = array(
    'title' => __('Upgrade authkeys to the advanced format'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Every existing plaintext API key is converted into a hashed advanced authkey so users do not lose access when the advanced format is enabled.')) . '</p>',
    'label' => __('Upgrade authkeys'), 'cls' => 'btn-primary',
);
$confirmations[$uid . '-orphan-attr'] = array(
    'title' => __('Remove orphaned attributes'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Attributes that no longer belong to any event are deleted. Run the check first to see how many there are.')) . '</p>',
    'label' => __('Remove them'), 'cls' => 'btn-danger',
);
$confirmations[$uid . '-orphan-corr'] = array(
    'title' => __('Remove orphaned correlations'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Correlations pointing at attributes that no longer exist are deleted.')) . '</p>',
    'label' => __('Remove them'), 'cls' => 'btn-danger',
);
$confirmations[$uid . '-cull'] = array(
    'title' => __('Remove published empty events'),
    'body' => '<p class="mb-0 text-muted small">' . h(__('Published events holding no attribute, object or report are deleted.')) . '</p>',
    'label' => __('Remove them'), 'cls' => 'btn-danger',
);

?>
<div class="card shadow-sm mb-4 ss-section dg-card" style="--ss-accent: #495057;">
    <div class="card-header ss-section-header" style="cursor: default;">
        <span class="ss-section-icon"><i class="fas fa-screwdriver-wrench"></i></span>
        <div class="flex-grow-1 min-w-0">
            <div class="fw-semibold"><?= __('Maintenance & tools') ?></div>
            <div class="text-muted" style="font-size:.78rem;"><?= __('One-off checks and clean-up routines for this instance') ?></div>
        </div>
    </div>
    <div class="card-body">
    <div class="dg-block-title"><?= __('Consistency checks') ?></div>

    <div class="dg-row">
        <span class="dg-row-label"><?= __('Orphaned attributes') ?></span>
        <span class="ms-auto d-flex align-items-center gap-2">
            <span class="dg-figures text-muted" data-dg-out="orphan-attr"><?= __('not checked') ?></span>
            <button type="button" class="btn btn-sm btn-outline-secondary"
                    data-dg-check="orphan-attr"><?= __('Check') ?></button>
        </span>
    </div>

    <div class="dg-row">
        <span class="dg-row-label"><?= __('Attachments referenced but missing on disk') ?></span>
        <span class="ms-auto d-flex align-items-center gap-2">
            <span class="dg-figures text-muted" data-dg-out="bad-attachments"><?= __('not checked') ?></span>
            <button type="button" class="btn btn-sm btn-outline-secondary"
                    data-dg-check="bad-attachments"><?= __('Check') ?></button>
        </span>
    </div>

    <div class="dg-row">
        <span class="dg-row-label"><?= __('Deprecated endpoint usage') ?></span>
        <span class="ms-auto">
            <button type="button" class="btn btn-sm btn-outline-secondary"
                    data-dg-check="deprecated"><?= __('View usage') ?></button>
        </span>
    </div>
    <div class="dg-raw mt-2 d-none" data-dg-out="deprecated-body"></div>

    <div class="dg-block-title mt-3"><?= __('Clean-up') ?></div>
    <div class="d-flex flex-wrap gap-2">
        <button type="button" class="btn btn-sm btn-outline-primary" onclick="dgConfirm('<?= h($uid) ?>-cache')">
            <i class="fas fa-broom me-1"></i><?= __('Clean model cache') ?>
        </button>
        <button type="button" class="btn btn-sm btn-outline-primary" onclick="dgConfirm('<?= h($uid) ?>-authkeys')">
            <i class="fas fa-key me-1"></i><?= __('Upgrade authkeys') ?>
        </button>
        <button type="button" class="btn btn-sm btn-outline-danger" onclick="dgConfirm('<?= h($uid) ?>-orphan-attr')">
            <i class="fas fa-trash me-1"></i><?= __('Remove orphaned attributes') ?>
        </button>
        <button type="button" class="btn btn-sm btn-outline-danger" onclick="dgConfirm('<?= h($uid) ?>-orphan-corr')">
            <i class="fas fa-trash me-1"></i><?= __('Remove orphaned correlations') ?>
        </button>
        <button type="button" class="btn btn-sm btn-outline-danger" onclick="dgConfirm('<?= h($uid) ?>-cull')">
            <i class="fas fa-trash me-1"></i><?= __('Remove published empty events') ?>
        </button>
    </div>

    <?= $this->Form->postLink('', $baseurl . '/servers/cleanModelCaches',
        array('id' => $uid . '-cache', 'class' => 'd-none', 'escape' => false)) ?>
    <?= $this->Form->postLink('', $baseurl . '/users/updateToAdvancedAuthKeys',
        array('id' => $uid . '-authkeys', 'class' => 'd-none', 'escape' => false)) ?>
    <?= $this->Form->postLink('', $baseurl . '/attributes/pruneOrphanedAttributes',
        array('id' => $uid . '-orphan-attr', 'class' => 'd-none', 'escape' => false)) ?>
    <?= $this->Form->postLink('', $baseurl . '/servers/removeOrphanedCorrelations',
        array('id' => $uid . '-orphan-corr', 'class' => 'd-none', 'escape' => false)) ?>
    <?= $this->Form->postLink('', $baseurl . '/events/cullEmptyEvents',
        array('id' => $uid . '-cull', 'class' => 'd-none', 'escape' => false)) ?>

    <div class="dg-block-title mt-3"><?= __('Other pages') ?></div>
    <div class="d-flex flex-wrap gap-2">
        <a href="<?= h($baseurl . '/servers/ondemandAction/') ?>" class="btn btn-sm btn-outline-secondary">
            <i class="fas fa-bolt me-1"></i><?= __('On-demand actions') ?>
        </a>
        <a href="<?= h($baseurl . '/events/restoreDeletedEvents') ?>" class="btn btn-sm btn-outline-secondary">
            <i class="fas fa-trash-arrow-up me-1"></i><?= __('Recover deleted events') ?>
        </a>
        <a href="<?= h($baseurl . '/pages/display/administration') ?>" class="btn btn-sm btn-outline-secondary">
            <i class="fas fa-clock-rotate-left me-1"></i><?= __('Legacy administrative tools') ?>
        </a>
    </div>
    </div>
</div>
<script type="application/json" data-ss-confirmations><?= json_encode($confirmations, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?></script>
</div>
