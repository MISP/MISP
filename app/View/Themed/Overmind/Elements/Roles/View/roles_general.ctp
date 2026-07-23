<?php
// view_layout only forwards `data` to the partial; pull the role metadata that
// the controller set() from the shared view vars.
$permFlags = $this->viewVars['permFlags'] ?? [];
$permissionLevelName = $this->viewVars['permissionLevelName'] ?? [];
$role = $data['Role'] ?? [];
$permission = $role['permission'] ?? null;
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- NAME -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1">
                <?= __('Name') ?>
            </div>
            <div class="fw-semibold fs-5">
                <?= h($role['name'] ?? '') ?>
            </div>
        </div>

        <!-- META GRID -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('ID') ?></div>
                <div class="bg-light rounded px-2 py-1 border">
                    <?= h($role['id'] ?? '') ?>
                </div>
            </div>
            <div class="col-md-9">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Permission level') ?></div>
                <div class="bg-light rounded px-2 py-1 border">
                    <?= h($permissionLevelName[$permission] ?? $permission) ?>
                </div>
            </div>
        </div>

        <!-- PERMISSION FLAGS -->
        <div class="text-muted small text-uppercase fw-bold mb-2">
            <?= __('Permission flags') ?>
        </div>
        <div class="row g-2">
            <?php foreach ($permFlags as $permFlag => $permFlagData): ?>
                <?php $granted = !empty($role[$permFlag]); ?>
                <div class="col-md-6 col-lg-4">
                    <div class="d-flex align-items-center justify-content-between border rounded px-2 py-1"
                         title="<?= h($permFlagData['title'] ?? '') ?>">
                        <span class="text-truncate me-2"><?= h($permFlagData['text']) ?></span>
                        <?php if ($granted): ?>
                            <span class="badge bg-success"><?= __('Granted') ?></span>
                        <?php else: ?>
                            <span class="badge bg-secondary"><?= __('Denied') ?></span>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>

    </div>
</div>
