<?php
$cerebrate = $data['Cerebrate'] ?? [];
$owner = $data['Organisation'] ?? [];
$url = (string)($cerebrate['url'] ?? '');
$isLink = (bool)preg_match('/^https?:\/\//i', $url);
$hasKey = !empty($cerebrate['authkey']);

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

// Same wording as the add/edit form.
$flags = [
    [
        'on' => !empty($cerebrate['pull_orgs']),
        'colour' => 'primary',
        'icon' => 'fas fa-building',
        'label' => [__('Pull organisations'), __('Organisations not pulled')],
        'sub' => [__('Fetch the organisations this Cerebrate knows'), __('Its organisations are not fetched')],
    ],
    [
        'on' => !empty($cerebrate['pull_sharing_groups']),
        'colour' => 'primary',
        'icon' => 'misp-icon misp-icon-sharing-group misp-simple',
        'label' => [__('Pull sharing groups'), __('Sharing groups not pulled')],
        'sub' => [__('Fetch the sharing groups it publishes'), __('Its sharing groups are not fetched')],
    ],
    [
        'on' => !empty($cerebrate['skip_proxy']),
        'colour' => 'secondary',
        'icon' => 'fas fa-diagram-project',
        'label' => [__('Skip proxy'), __('Through the proxy')],
        'sub' => [__('Reached directly, ignoring the configured proxy'), __('Reached through the configured proxy, if any')],
    ],
];
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>">
                <i class="fas fa-brain text-primary me-1"></i><?= __('Cerebrate') ?>
            </div>
            <?php if (trim($cerebrate['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 text-break">
                    <?= nl2br(h($cerebrate['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Connection') ?></div>
            <div class="d-flex flex-wrap align-items-center gap-2">
                <?php if ($url === ''): ?>
                    <span class="text-body-secondary fst-italic small"><?= __('No URL') ?></span>
                <?php else: ?>
                    <div class="d-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden lh-base mw-100" style="width:fit-content;">
                        <?php if ($isLink): ?>
                            <a class="d-inline-flex align-items-center gap-1 px-2 text-truncate text-decoration-none small"
                               href="<?= h($url) ?>" rel="noreferrer noopener" target="_blank" title="<?= h($url) ?>">
                                <i class="fas fa-arrow-up-right-from-square opacity-50"></i><span class="text-truncate"><?= h($url) ?></span>
                            </a>
                        <?php else: ?>
                            <span class="d-inline-flex align-items-center gap-1 px-2 text-truncate small text-body-emphasis" title="<?= h($url) ?>">
                                <i class="fas fa-globe opacity-50"></i><span class="text-truncate"><?= h($url) ?></span>
                            </span>
                        <?php endif; ?>
                        <span class="vr my-1"></span>
                        <button type="button" class="ov-copy-target focus-ring d-inline-flex align-items-center border-0 bg-transparent text-body-secondary px-2 mb-0"
                                title="<?= h(__('Copy the URL')) ?>" aria-label="<?= h(__('Copy the URL')) ?>"
                                data-copy-value="<?= h($url) ?>" data-copy-msg="<?= h(__('URL copied to clipboard')) ?>"
                                onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">
                            <i class="fas fa-copy fa-xs opacity-100 text-body-emphasis"></i>
                        </button>
                    </div>
                <?php endif; ?>
                <span class="badge rounded-pill fw-normal <?= $hasKey ? 'text-bg-success' : 'bg-warning-subtle text-warning-emphasis border border-warning-subtle' ?>"
                      title="<?= h($hasKey ? __('The key itself is never displayed') : __('Calls to this Cerebrate cannot authenticate until a key is set')) ?>">
                    <i class="fas <?= $hasKey ? 'fa-key' : 'fa-triangle-exclamation' ?> me-1"></i><?= $hasKey ? __('Auth key configured') : __('No auth key') ?>
                </span>
            </div>
        </div>

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
            </div>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Owner') ?></div>
            <div class="d-flex align-items-center gap-2 min-w-0">
                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden" style="<?= $tileStyle ?>">
                    <?= (!empty($owner['id']) ? $this->OrgImg->getOrgLogoV2($owner, 20, false) : '') ?: '<i class="fas fa-building text-body-secondary"></i>' ?>
                </span>
                <div class="min-w-0">
                    <?php if (!empty($owner['id'])): ?>
                        <a class="d-block fw-semibold lh-sm text-truncate text-decoration-none"
                           href="<?= h($baseurl . '/organisations/view/' . $owner['id']) ?>"><?= h($owner['name'] ?? '') ?></a>
                    <?php else: ?>
                        <div class="fw-semibold lh-sm"><?= __('System') ?></div>
                    <?php endif; ?>
                    <div class="small text-body-secondary"><?= __('Organisation that set up this connection') ?></div>
                </div>
            </div>
        </div>

    </div>
</div>
