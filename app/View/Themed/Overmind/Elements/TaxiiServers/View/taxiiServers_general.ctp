<?php
$server = $data['TaxiiServer'] ?? [];

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

/*
 * The credential never reaches the page. With basic auth api_key holds
 * base64(user:password), so only the user name is decoded out of it.
 */
$authType = (string)($server['auth_type'] ?? 'basic');
$hasKey = trim((string)($server['api_key'] ?? '')) !== '';
$basicUser = null;
if ($hasKey && $authType === 'basic') {
    $decoded = base64_decode((string)$server['api_key'], true);
    if ($decoded !== false && strpos($decoded, ':') !== false) {
        $basicUser = strstr($decoded, ':', true);
    }
}

$filters = json_decode((string)($server['filters'] ?? ''), true);
$filters = is_array($filters) ? $filters : [];

$urlPill = function ($url, $icon, $title) {
    $url = (string)$url;
    $isLink = (bool)preg_match('/^https?:\/\//i', $url);
    $value = '<span class="text-truncate">' . h($url) . '</span>';
    return '<div class="d-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden lh-base mw-100" style="width:fit-content;">'
        . ($isLink
            ? '<a class="d-inline-flex align-items-center gap-1 px-2 text-truncate text-decoration-none small" href="' . h($url) . '" rel="noreferrer noopener" target="_blank" title="' . h($title) . ': ' . h($url) . '"><i class="' . h($icon) . ' opacity-50"></i>' . $value . '</a>'
            : '<span class="d-inline-flex align-items-center gap-1 px-2 text-truncate small text-body-emphasis" title="' . h($title) . ': ' . h($url) . '"><i class="' . h($icon) . ' opacity-50"></i>' . $value . '</span>')
        . '<span class="vr my-1"></span>'
        . '<button type="button" class="ov-copy-target focus-ring d-inline-flex align-items-center border-0 bg-transparent text-body-secondary px-2 mb-0"'
        . ' title="' . h(__('Copy')) . '" aria-label="' . h(__('Copy')) . '"'
        . ' data-copy-value="' . h($url) . '" data-copy-msg="' . h(__('Copied to clipboard')) . '"'
        . ' onclick="copyValueToClipboard(this.dataset.copyValue, this.dataset.copyMsg)">'
        . '<i class="fas fa-copy fa-xs opacity-100 text-body-emphasis"></i></button></div>';
};

$flags = [
    [
        'on' => !empty($server['enabled']),
        'colour' => 'success',
        'icon' => 'fas fa-power-off',
        'label' => [__('Enabled'), __('Disabled')],
        'sub' => [__('Events can be pushed to it'), __('Nothing can be pushed to it')],
    ],
    [
        'on' => !empty($server['skip_proxy']),
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
                <i class="fas fa-tower-broadcast text-primary me-1"></i><?= __('TAXII server') ?>
            </div>
            <?php if (trim($server['description'] ?? '') !== ''): ?>
                <div class="border-start border-3 border-primary bg-primary-subtle bg-opacity-25 rounded-end px-3 py-2 text-break">
                    <?= nl2br(h($server['description'])) ?>
                </div>
            <?php else: ?>
                <span class="text-body-secondary fst-italic small"><?= __('No description') ?></span>
            <?php endif; ?>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Connection') ?></div>
            <div class="d-flex flex-column gap-2">
                <div class="d-flex flex-wrap align-items-center gap-2">
                    <span class="small text-body-secondary" style="width:6.5rem;"><?= __('Discovery') ?></span>
                    <?php if (!empty($server['discovery_url'])): ?>
                        <?= $urlPill($server['discovery_url'], 'fas fa-compass', __('Discovery URL')) ?>
                    <?php else: ?>
                        <span class="text-body-secondary fst-italic small"><?= __('Not set') ?></span>
                    <?php endif; ?>
                </div>
                <div class="d-flex flex-wrap align-items-center gap-2">
                    <span class="small text-body-secondary" style="width:6.5rem;"><?= __('API root') ?></span>
                    <?php if (!empty($server['api_root'])): ?>
                        <?= $urlPill($server['api_root'], 'fas fa-sitemap', __('API root')) ?>
                    <?php else: ?>
                        <span class="badge rounded-pill fw-normal bg-warning-subtle text-warning-emphasis border border-warning-subtle"><i class="fas fa-triangle-exclamation me-1"></i><?= __('Not set — collections and objects cannot be queried') ?></span>
                    <?php endif; ?>
                </div>
                <div class="d-flex flex-wrap align-items-center gap-2">
                    <span class="small text-body-secondary" style="width:6.5rem;"><?= __('Collection') ?></span>
                    <?php if (!empty($server['collection'])): ?>
                        <a href="#tab-objects" class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal font-monospace text-decoration-none"
                           data-taxii-tab="objects" title="<?= h(__('Browse its objects')) ?>">
                            <i class="fas fa-folder me-1 opacity-50"></i><?= h($server['collection']) ?>
                        </a>
                    <?php else: ?>
                        <a href="#tab-collections" class="small text-decoration-none" data-taxii-tab="collections"><?= __('None selected — pick one from the collections') ?></a>
                    <?php endif; ?>
                </div>
                <div class="d-flex flex-wrap align-items-center gap-2">
                    <span class="small text-body-secondary" style="width:6.5rem;"><?= __('Authentication') ?></span>
                    <?php if (!$hasKey): ?>
                        <span class="badge rounded-pill fw-normal bg-warning-subtle text-warning-emphasis border border-warning-subtle">
                            <i class="fas fa-triangle-exclamation me-1"></i><?= __('No credentials') ?>
                        </span>
                    <?php elseif ($authType === 'bearer'): ?>
                        <span class="badge rounded-pill fw-normal text-bg-success" title="<?= h(__('The token itself is never displayed')) ?>">
                            <i class="fas fa-key me-1"></i><?= __('Bearer token') ?>
                        </span>
                    <?php else: ?>
                        <span class="badge rounded-pill fw-normal text-bg-success" title="<?= h(__('The password itself is never displayed')) ?>">
                            <i class="fas fa-user-lock me-1"></i><?= __('Basic authentication') ?>
                        </span>
                        <?php if ($basicUser !== null && $basicUser !== ''): ?>
                            <span class="small text-body-secondary"><?= __('as') ?> <span class="font-monospace text-body-emphasis"><?= h($basicUser) ?></span></span>
                        <?php endif; ?>
                    <?php endif; ?>
                </div>
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
                <div class="d-flex align-items-center gap-2 min-w-0" style="flex:1 1 13rem;">
                    <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary text-body-secondary" style="<?= $tileStyle ?>">
                        <i class="fas fa-building"></i>
                    </span>
                    <div class="min-w-0">
                        <div class="fw-semibold lh-sm text-truncate"><?= h(($server['owner'] ?? '') !== '' ? $server['owner'] : __('Not set')) ?></div>
                        <div class="small text-body-secondary"><?= __('Owner') ?></div>
                    </div>
                </div>
            </div>
        </div>

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Push filters') ?></div>
            <?php if (empty($filters)): ?>
                <span class="text-body-secondary fst-italic small"><?= __('No filter — every event the user running the push can see is sent.') ?></span>
            <?php else: ?>
                <div class="d-flex flex-column gap-1 small">
                    <?php foreach ($filters as $key => $value): ?>
                        <div class="d-flex flex-wrap align-items-center gap-1">
                            <span class="fw-semibold font-monospace me-1"><?= h($key) ?></span>
                            <?php foreach ((array)$value as $item): ?>
                                <span class="badge rounded-pill border bg-body-tertiary text-body-emphasis fw-normal font-monospace">
                                    <?= h(is_scalar($item) ? (is_bool($item) ? ($item ? 'true' : 'false') : (string)$item) : json_encode($item)) ?>
                                </span>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

    </div>
</div>

<script>
(function () {
    document.querySelectorAll('[data-taxii-tab]:not([data-taxii-bound])').forEach(function (link) {
        link.setAttribute('data-taxii-bound', '');
        link.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-' + link.dataset.taxiiTab + '"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
})();
</script>
