<?php

$permFlags = $this->viewVars['permFlags'] ?? [];
$permissionLevelName = $this->viewVars['permissionLevelName'] ?? [];
$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$role = $data['Role'] ?? [];
$permission = $role['permission'] ?? null;
$roleId = $role['id'] ?? null;
?>


<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- META GRID -->
        <div class="row g-3 mb-4">
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('ID') ?></div>
                <div class="bg-light rounded px-2 py-1 border">
                    <?= h($roleId ?? '') ?>
                </div>
            </div>
            <div class="col-md-9">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Permission level') ?></div>
                <div class="bg-light rounded px-2 py-1 border">
                    <?= h($permissionLevelName[$permission] ?? $permission) ?>
                </div>
            </div>
        </div>

        <!-- RESOURCE LIMITS -->
        <?php
            $defaultMemoryLimit = $this->viewVars['default_memory_limit'] ?? '';
            $defaultMaxExecTime = $this->viewVars['default_max_execution_time'] ?? '';

            $memoryLimit = empty($role['memory_limit']) ? $defaultMemoryLimit : $role['memory_limit'];
            $maxExecTime = empty($role['max_execution_time']) ? $defaultMaxExecTime : $role['max_execution_time'];
            $enforceRate = !empty($role['enforce_rate_limit']);
            $rateLimit = (empty($role['enforce_rate_limit']) || empty($role['rate_limit_count']))
                ? __('Unlimited')
                : $role['rate_limit_count'];

            $restDefault = (int) Configure::read('MISP.default_restsearch_limit');
            $restValue = array_key_exists('restsearch_limit_result', $role) ? $role['restsearch_limit_result'] : null;
            $restLimited = !is_null($restValue);
            if ($restLimited) {
                $restNumber = empty($restValue) ? __('Unlimited') : $restValue; // 0 == unlimited
                $restFallback = null;
            } else {
                $restNumber = null;
                if (!empty($role['perm_site_admin'])) {
                    $restFallback = __('Fallback to Unlimited as Site Admin');
                } elseif ($restDefault == 0) {
                    $restFallback = __('Fallback to server default (Unlimited)');
                } else {
                    $restFallback = __('Fallback to server default (%s)', $restDefault);
                }
            }
        ?>
        <div class="row g-3 mb-4">
            <div class="col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Memory limit (%s)', h($defaultMemoryLimit)) ?></div>
                <div class="bg-light rounded px-2 py-1 border"><?= h($memoryLimit) ?></div>
            </div>
            <div class="col-md-6">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Maximum execution time (%ss)', h($defaultMaxExecTime)) ?></div>
                <div class="bg-light rounded px-2 py-1 border"><?= h($maxExecTime) ?>&nbsp;s</div>
            </div>
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Enforce search rate limit') ?></div>
                <div class="pt-1">
                    <?php if ($enforceRate): ?>
                        <span class="badge bg-success"><?= __('Enabled') ?></span>
                    <?php else: ?>
                        <span class="badge bg-secondary"><?= __('Disabled') ?></span>
                    <?php endif; ?>
                </div>
            </div>
            <div class="col-md-9">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('# of searches / 15 min') ?></div>
                <div class="bg-light rounded px-2 py-1 border"><?= h($rateLimit) ?></div>
            </div>
            <div class="col-md-3">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Limit restSearch results') ?></div>
                <div class="pt-1 d-flex align-items-center flex-wrap gap-2">
                    <?php if ($restLimited): ?>
                        <span class="badge bg-success"><?= __('Enabled') ?></span>
                    <?php else: ?>
                        <span class="badge bg-secondary"><?= __('Disabled') ?></span>
                        <span class="text-muted small"><?= h($restFallback) ?></span>
                    <?php endif; ?>
                </div>
            </div>
            <div class="col-md-9">
                <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('# of results / restSearch') ?></div>
                <?php if ($restLimited): ?>
                    <div class="bg-light rounded px-2 py-1 border"><?= h($restNumber) ?></div>
                <?php else: ?>
                    <div class="bg-light rounded px-2 py-1 border text-muted">&mdash;</div>
                <?php endif; ?>
            </div>
        </div>

        <!-- PERMISSION FLAGS -->
        <div class="text-muted small text-uppercase fw-bold mb-2">
            <?= __('Permission flags') ?>
            <?php if ($isSiteAdmin): ?>
                <span class="fw-normal text-body-secondary text-lowercase ms-1">
                    (<?= __('click a permission to toggle it') ?>)
                </span>
            <?php endif; ?>
        </div>
        <div class="row g-2">
            <?php foreach ($permFlags as $permFlag => $permFlagData): ?>
                <?php
                    $granted = !empty($role[$permFlag]);
                    $toggleUrl = $isSiteAdmin && $roleId !== null
                        ? $baseurl . '/admin/roles/togglePermission/' . h($roleId) . '/' . h($permFlag)
                        : null;
                ?>
                <div class="col-md-6 col-lg-4">
                    <div class="d-flex align-items-center justify-content-between border rounded px-2 py-1<?= $toggleUrl ? ' perm-flag-toggle' : '' ?>"
                         title="<?= h($permFlagData['title'] ?? '') ?>"
                         <?php if ($toggleUrl): ?>role="button" tabindex="0" onclick="openModal('<?= h($toggleUrl) ?>', 'md')"<?php endif; ?>>
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
