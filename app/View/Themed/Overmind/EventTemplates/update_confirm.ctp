<?php
/*
 * BS5 confirm page for /event_templates/update (GET). Mirrors the
 * default-theme `update_confirm.ctp` shape with Bootstrap 5 cards.
 */
$present = isset($preview['present_in_library']) ? $preview['present_in_library'] : array();
$failed = isset($preview['failed']) ? $preview['failed'] : array();

$buckets = array('install' => array(), 'managed' => array(), 'forked' => array());
foreach ($present as $row) {
    if (empty($row['local'])) {
        $buckets['install'][] = $row;
    } elseif ((int)$row['local']['misp_default'] === 1) {
        $buckets['managed'][] = $row;
    } else {
        $buckets['forked'][] = $row;
    }
}
$renderBucket = function ($rows) use ($baseurl) {
    if (empty($rows)) {
        return '<div class="text-muted fst-italic small">' . __('Nothing in this bucket.') . '</div>';
    }
    $items = '';
    foreach ($rows as $r) {
        $name = h($r['name'] ?? '');
        $linkOpen = !empty($r['local']['id'])
            ? sprintf('<a href="%s">', h($baseurl . '/event_templates/view/' . (int)$r['local']['id']))
            : '';
        $linkClose = !empty($r['local']['id']) ? '</a>' : '';
        $items .= sprintf(
            '<li class="list-group-item d-flex justify-content-between">'
            . '<span>%s%s%s</span>'
            . '<code class="text-muted">%s</code>'
            . '</li>',
            $linkOpen, $name, $linkClose,
            h($r['slug'] ?? '')
        );
    }
    return '<ul class="list-group list-group-flush">' . $items . '</ul>';
};
?>
<div class="container-fluid mt-3">
    <h2 class="fw-semibold mb-3"><?= __('Update event templates from library') ?></h2>

    <p class="text-muted">
        <?= __('This walks the bundled <code>misp-event-templates</code> submodule and reconciles its content with the local <code>event_templates</code> table.') ?>
    </p>
    <p class="text-muted small">
        <?= __('Effect: rows missing locally are <em>installed</em>; rows already present and library-managed (<code>misp_default = 1</code>) are <em>updated</em> if upstream content differs; rows the operator has explicitly forked (<code>misp_default = 0</code>) are <em>skipped</em>.') ?>
    </p>

    <?php if (!empty($failed)): ?>
        <div class="alert alert-danger">
            <strong><?= __('%d on-disk template(s) could not be parsed:', count($failed)) ?></strong>
            <ul class="mb-0 mt-2">
                <?php foreach ($failed as $f): ?>
                    <li><code><?= h($f['slug'] ?? '(no slug)') ?></code> — <?= h($f['error']) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <div class="row g-3">
        <div class="col-md-4">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-success-subtle fw-semibold">
                    <i class="fas fa-plus-circle me-1"></i>
                    <?= __('Will install') ?>
                    <span class="badge bg-success ms-2"><?= count($buckets['install']) ?></span>
                </div>
                <?= $renderBucket($buckets['install']) ?>
                <?php if (!empty($buckets['install'])): ?>
                    <div class="card-footer text-muted small">
                        <?= __('New rows will be created with <code>active = 0</code> and <code>distribution = 1</code>.') ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="col-md-4">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-primary-subtle fw-semibold">
                    <i class="fas fa-sync me-1"></i>
                    <?= __('May update') ?>
                    <span class="badge bg-primary ms-2"><?= count($buckets['managed']) ?></span>
                </div>
                <?= $renderBucket($buckets['managed']) ?>
                <?php if (!empty($buckets['managed'])): ?>
                    <div class="card-footer text-muted small">
                        <?= __('Rows whose upstream content changed will be overwritten; identical content stays untouched.') ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>

        <div class="col-md-4">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-warning-subtle fw-semibold">
                    <i class="fas fa-code-fork me-1"></i>
                    <?= __('Will skip (forked)') ?>
                    <span class="badge bg-warning text-dark ms-2"><?= count($buckets['forked']) ?></span>
                </div>
                <?= $renderBucket($buckets['forked']) ?>
                <?php if (!empty($buckets['forked'])): ?>
                    <div class="card-footer text-muted small">
                        <?= __('Operator-forked rows. Flip <code>misp_default</code> back via the builder to re-opt-in.') ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <?php
        echo $this->Form->create('EventTemplate', array(
            'url' => array('controller' => 'event_templates', 'action' => 'update'),
            'type' => 'post',
            'class' => 'mt-4',
        ));
    ?>
        <button type="submit" class="btn btn-primary">
            <i class="fas fa-sync me-1"></i><?= __('Apply update') ?>
        </button>
        <a href="<?= h($baseurl . '/event_templates/index') ?>" class="btn btn-outline-secondary">
            <?= __('Cancel') ?>
        </a>
    <?= $this->Form->end() ?>
</div>
