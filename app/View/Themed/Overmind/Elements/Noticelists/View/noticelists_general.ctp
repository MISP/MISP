<?php
$noticelist = $data['Noticelist'] ?? [];
$areas = array_filter((array)($noticelist['geographical_area'] ?? []));
$refs = array_filter((array)($noticelist['ref'] ?? []));
$enabled = !empty($noticelist['enabled']);

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>">
                    <i class="fas fa-bullhorn text-primary me-1"></i><?= __('Noticelist') ?>
                </span>
                <span class="badge rounded-pill bg-primary-subtle text-primary-emphasis border border-primary-subtle">
                    v<?= h((int)($noticelist['version'] ?? 0)) ?>
                </span>
            </div>
            <?php if (trim($noticelist['expanded_name'] ?? '') !== ''): ?>
                <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 fw-semibold text-break">
                    <?= h($noticelist['expanded_name']) ?>
                </div>
            <?php endif; ?>
        </div>

        <div class="d-flex flex-wrap row-gap-3 column-gap-4">
            <div class="min-w-0" style="flex:1 1 13rem;">
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Applies in') ?></div>
                <?php if (empty($areas)): ?>
                    <span class="small text-body-secondary fst-italic"><?= __('Anywhere') ?></span>
                <?php else: ?>
                    <div class="d-flex flex-wrap gap-1">
                        <?php foreach ($areas as $area): ?>
                            <span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal">
                                <i class="fas fa-earth-europe me-1 opacity-50"></i><?= h(strtoupper($area)) ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <div class="min-w-0" style="flex:2 1 16rem;">
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('References') ?></div>
                <?php if (empty($refs)): ?>
                    <span class="small text-body-secondary fst-italic"><?= __('None') ?></span>
                <?php else: ?>
                    <div class="d-flex flex-wrap gap-1">
                        <?php foreach ($refs as $ref): ?>
                            <?php if (preg_match('/^https?:\/\//i', $ref)): ?>
                                <a class="badge rounded-pill border bg-body text-body-secondary fw-normal text-decoration-none text-truncate" style="max-width:24rem;"
                                   href="<?= h($ref) ?>" rel="noreferrer noopener" target="_blank" title="<?= h($ref) ?>">
                                    <i class="fas fa-arrow-up-right-from-square me-1 opacity-50"></i><?= h(parse_url($ref, PHP_URL_HOST) ?: $ref) ?>
                                </a>
                            <?php else: ?>
                                <span class="badge rounded-pill border bg-body text-body-secondary fw-normal"><?= h($ref) ?></span>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <div class="d-flex align-items-center gap-2 min-w-0<?= $enabled ? '' : ' opacity-75' ?>" style="flex:1 1 13rem;">
                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $enabled ? 'bg-success-subtle text-success-emphasis' : 'bg-body-secondary text-body-secondary' ?>"
                      style="<?= $tileStyle ?>">
                    <i class="fas fa-power-off"></i>
                </span>
                <div class="min-w-0">
                    <div class="fw-semibold lh-sm<?= $enabled ? '' : ' text-body-secondary' ?>"><?= $enabled ? __('Enabled') : __('Disabled') ?></div>
                    <div class="small text-body-secondary"><?= $enabled ? __('Its notices are raised on matching attributes') : __('Its notices are not raised') ?></div>
                </div>
            </div>
        </div>

    </div>
</div>
