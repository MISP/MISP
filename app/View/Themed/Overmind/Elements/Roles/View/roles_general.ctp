<?php
$permFlags = $this->viewVars['permFlags'] ?? [];
$permissionLevelName = $this->viewVars['permissionLevelName'] ?? [];
$isSiteAdmin = $this->viewVars['isSiteAdmin'] ?? false;
$role = $data['Role'] ?? [];
$roleId = $role['id'] ?? null;
$level = (int)($role['permission'] ?? 0);
$userCount = $roleUserCount ?? null;

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

// What each step of Role::$permissionLevelName lets a user do with events.
$levelGlosses = [
    __('Can view events, but not create or edit them'),
    __('Can create events and edit the ones it created'),
    __('Can edit every event of its organisation'),
    __('Can edit and publish every event of its organisation'),
];

$defaultMemoryLimit = (string)($this->viewVars['default_memory_limit'] ?? '');
$defaultMaxExecTime = (string)($this->viewVars['default_max_execution_time'] ?? '');
$restDefault = (int)Configure::read('MISP.default_restsearch_limit');
$restValue = array_key_exists('restsearch_limit_result', $role) ? $role['restsearch_limit_result'] : null;
if ($restValue !== null) {
    $restLimit = empty($restValue) ? __('Unlimited') : __n('%s result', '%s results', (int)$restValue, number_format((int)$restValue, 0, ',', ' '));
    $restSub = __('Per restSearch call');
} elseif (!empty($role['perm_site_admin'])) {
    $restLimit = __('Unlimited');
    $restSub = __('As a site admin role');
} else {
    $restLimit = $restDefault === 0 ? __('Unlimited') : __n('%s result', '%s results', $restDefault, number_format($restDefault, 0, ',', ' '));
    $restSub = __('Server default, per restSearch call');
}

$limits = [
    [
        'icon' => 'fas fa-memory',
        'value' => !empty($role['memory_limit']) ? $role['memory_limit'] : $defaultMemoryLimit,
        'sub' => !empty($role['memory_limit']) ? __('Memory limit') : __('Memory limit, server default'),
    ],
    [
        'icon' => 'fas fa-stopwatch',
        'value' => (!empty($role['max_execution_time']) ? $role['max_execution_time'] : $defaultMaxExecTime) . ' s',
        'sub' => !empty($role['max_execution_time']) ? __('Maximum execution time') : __('Maximum execution time, server default'),
    ],
    [
        'icon' => 'fas fa-gauge-high',
        'value' => (!empty($role['enforce_rate_limit']) && !empty($role['rate_limit_count']))
            ? __('%s searches', number_format((int)$role['rate_limit_count'], 0, ',', ' '))
            : __('Unlimited'),
        'sub' => __('Search rate per 15 minutes'),
    ],
    [
        'icon' => 'fas fa-filter',
        'value' => $restLimit,
        'sub' => $restSub,
    ],
];

$granted = 0;
foreach ($permFlags as $flag => $flagData) {
    if (!empty($role[$flag])) {
        $granted++;
    }
}
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div class="d-flex align-items-center justify-content-between flex-wrap gap-2">
            <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                <i class="fas fa-user-tag text-primary me-1"></i><?= __('Role') ?>
            </span>
            <span class="d-flex flex-wrap align-items-center gap-1">
                <?php if (!empty($role['default_role'])): ?>
                    <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle fw-normal"
                          title="<?= h(__('Given to new users unless another role is chosen')) ?>">
                        <i class="fas fa-star me-1"></i><?= __('Default role') ?>
                    </span>
                <?php endif; ?>
                <?php if (!empty($role['restricted_to_site_admin'])): ?>
                    <span class="badge rounded-pill bg-warning-subtle text-warning-emphasis border border-warning-subtle fw-normal"
                          title="<?= h(__('Organisation admins cannot give this role')) ?>">
                        <i class="fas fa-lock me-1"></i><?= __('Site admins assign it') ?>
                    </span>
                <?php endif; ?>
                <?php if ($userCount !== null): ?>
                    <a class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal text-decoration-none"
                       href="<?= h($baseurl . '/admin/users/index/searchrole:' . (int)$roleId) ?>" title="<?= h(__('Show these users')) ?>">
                        <i class="fas fa-users me-1 opacity-50"></i><?= h(__n('%s user', '%s users', $userCount, $userCount)) ?>
                    </a>
                <?php endif; ?>
            </span>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-2" style="<?= $labelStyle ?>"><?= __('Event access') ?></div>
            <div class="d-grid gap-1" role="meter" aria-valuemin="0" aria-valuemax="<?= count($permissionLevelName) - 1 ?>"
                 aria-valuenow="<?= $level ?>" aria-label="<?= h(__('Event access')) ?>"
                 style="grid-template-columns:repeat(<?= count($permissionLevelName) ?>, minmax(0, 1fr));">
                <?php foreach ($permissionLevelName as $step => $name): ?>
                    <div class="d-flex flex-column gap-1 min-w-0">
                        <span class="d-block rounded-pill <?= $step <= $level ? 'bg-primary' : 'bg-body-secondary' ?>" style="height:.4rem;"></span>
                        <span class="small text-center text-truncate <?= $step === $level ? 'fw-semibold text-primary-emphasis' : 'text-body-secondary' ?>"
                              title="<?= h($name) ?>"><?= h($name) ?></span>
                    </div>
                <?php endforeach; ?>
            </div>
            <div class="small text-body-secondary mt-1"><?= h($levelGlosses[$level] ?? '') ?></div>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Limits') ?></div>
            <div class="row row-cols-1 row-cols-sm-2 row-cols-xl-4 g-2">
                <?php foreach ($limits as $limit): ?>
                    <div class="col">
                        <div class="d-flex align-items-center gap-2 min-w-0">
                            <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary text-body-secondary" style="<?= $tileStyle ?>">
                                <i class="<?= h($limit['icon']) ?>"></i>
                            </span>
                            <div class="min-w-0">
                                <div class="fw-semibold lh-sm text-truncate"><?= h($limit['value']) ?></div>
                                <div class="small text-body-secondary text-truncate" title="<?= h($limit['sub']) ?>"><?= h($limit['sub']) ?></div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>"><?= __('Permissions') ?></span>
                <span class="small text-body-secondary">
                    <?= h(__('%s of %s granted', $granted, count($permFlags))) ?>
                    <?php if ($isSiteAdmin): ?> &middot; <?= __('click one to toggle it') ?><?php endif; ?>
                </span>
            </div>
            <div class="row row-cols-1 row-cols-md-2 row-cols-xl-3 g-1">
                <?php foreach ($permFlags as $permFlag => $permFlagData): ?>
                    <?php
                    $isGranted = !empty($role[$permFlag]);
                    $toggleUrl = $isSiteAdmin && $roleId !== null
                        ? $baseurl . '/admin/roles/togglePermission/' . (int)$roleId . '/' . h($permFlag)
                        : null;
                    $inner = '<i class="fas ' . ($isGranted ? 'fa-circle-check text-success' : 'fa-circle-xmark text-body-secondary opacity-50') . ' flex-shrink-0"></i>'
                        . '<span class="text-truncate' . ($isGranted ? ' fw-semibold' : ' text-body-secondary') . '">' . h($permFlagData['text']) . '</span>';
                    ?>
                    <div class="col">
                        <?php if ($toggleUrl): ?>
                            <button type="button" class="btn btn-sm w-100 d-flex align-items-center gap-2 text-start border-0 rounded-2 px-2 py-1 perm-flag-toggle<?= $isGranted ? ' bg-success-subtle' : '' ?>"
                                    title="<?= h($permFlagData['title'] ?? '') ?>"
                                    onclick="openModal('<?= h($toggleUrl) ?>', 'md')"><?= $inner ?></button>
                        <?php else: ?>
                            <div class="d-flex align-items-center gap-2 rounded-2 px-2 py-1 small<?= $isGranted ? ' bg-success-subtle' : '' ?>"
                                 title="<?= h($permFlagData['title'] ?? '') ?>"><?= $inner ?></div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

    </div>
</div>
