<?php
$objectTemplate = $data['ObjectTemplate'] ?? [];
$organisation = $data['Organisation'] ?? [];
$creator = $data['User'] ?? [];
$requirements = is_array($objectTemplate['requirements'] ?? null) ? $objectTemplate['requirements'] : [];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$requirementGroups = [
    'required' => [__('Required'), __('Every one of these must be filled'), 'danger'],
    'requiredOneOf' => [__('At least one of'), __('One of these is enough'), 'warning'],
];

$flags = [
    [
        'on' => !empty($objectTemplate['active']),
        'colour' => 'success',
        'icon' => 'fas fa-power-off',
        'label' => [__('Active'), __('Inactive')],
        'sub' => [__('Offered when adding an object'), __('Not offered when adding an object')],
    ],
    [
        'on' => !empty($objectTemplate['fixed']),
        'colour' => 'primary',
        'icon' => 'fas fa-box',
        'label' => [__('Library'), __('Custom')],
        'sub' => [__('Installed from the misp-objects library'), __('Created on this instance')],
    ],
];
?>
<div class="card mb-3 shadow-sm" data-tour="object-template-general">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="misp-icon misp-icon-object misp-simple me-1" style="color:rgb(var(--bs-object-rgb));"></i><?= __('Object template') ?>
                </span>
                <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                    v<?= h((int)($objectTemplate['version'] ?? 0)) ?>
                </span>
            </div>
            <?php if (trim($objectTemplate['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 rounded-end px-3 py-2 text-break"
                     style="border-color:rgb(var(--bs-object-rgb)) !important;background:rgba(var(--bs-object-rgb),.06);">
                    <?= nl2br(h($objectTemplate['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <?php if (!empty(array_intersect_key($requirements, $requirementGroups))): ?>
            <div>
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Requirements') ?></div>
                <div class="d-flex flex-column gap-2">
                    <?php foreach ($requirementGroups as $group => list($label, $gloss, $colour)): ?>
                        <?php if (empty($requirements[$group])): continue; endif; ?>
                        <div class="d-flex flex-column flex-md-row gap-1 gap-md-3">
                            <div class="flex-shrink-0" style="width:9rem;">
                                <div class="small fw-semibold text-<?= $colour ?>-emphasis"><?= h($label) ?></div>
                                <div class="text-body-secondary" style="font-size:.75rem;"><?= h($gloss) ?></div>
                            </div>
                            <div class="d-flex flex-wrap align-items-center gap-1 min-w-0">
                                <?php foreach ((array)$requirements[$group] as $relation): ?>
                                    <span class="badge rounded-pill fw-normal font-monospace bg-<?= $colour ?>-subtle text-<?= $colour ?>-emphasis border border-<?= $colour ?>-subtle">
                                        <?= h($relation) ?>
                                    </span>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Settings') ?></div>
            <div class="d-flex flex-wrap row-gap-2 column-gap-3">
                <?php foreach ($flags as $flag): ?>
                    <?php $state = $flag['on'] ? 0 : 1; ?>
                    <div class="d-flex align-items-center gap-2 min-w-0<?= $flag['on'] ? '' : ' opacity-75' ?>" style="flex:1 1 13rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $flag['on']
                            ? 'bg-' . $flag['colour'] . '-subtle text-' . $flag['colour'] . '-emphasis'
                            : 'bg-body-secondary text-body-secondary' ?>"
                              style="<?= $tileStyle ?>">
                            <i class="<?= h($flag['icon']) ?>"></i>
                        </span>
                        <div class="min-w-0">
                            <div class="fw-semibold lh-sm<?= $flag['on'] ? '' : ' text-body-secondary' ?>"><?= h($flag['label'][$state]) ?></div>
                            <div class="small text-body-secondary text-truncate" title="<?= h($flag['sub'][$state]) ?>"><?= h($flag['sub'][$state]) ?></div>
                        </div>
                    </div>
                <?php endforeach; ?>
                <?php if (!empty($organisation['name'])): ?>
                    <div class="d-flex align-items-center gap-2 min-w-0" style="flex:1 1 13rem;">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden"
                              style="<?= $tileStyle ?>">
                            <?= $this->OrgImg->getOrgLogoV2($organisation, 20, false)
                                ?: '<i class="fas fa-building text-body-secondary"></i>' ?>
                        </span>
                        <div class="min-w-0">
                            <a class="d-block fw-semibold lh-sm text-truncate text-decoration-none"
                               href="<?= h($baseurl . '/organisations/view/' . $organisation['id']) ?>"><?= h($organisation['name']) ?></a>
                            <div class="small text-body-secondary text-truncate">
                                <?= !empty($objectTemplate['fixed']) ? __('Installed by') : __('Created by') ?><?php if (!empty($creator['email'])): ?> &middot; <?= h($creator['email']) ?><?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>

    </div>
</div>
