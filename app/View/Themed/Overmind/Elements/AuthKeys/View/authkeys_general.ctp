<?php
$key = $data['AuthKey'] ?? [];
$user = $data['User'] ?? [];
$keyId = (int)($key['id'] ?? 0);

$labelClass = 'text-body-secondary text-uppercase fw-bold';
$labelStyle = 'font-size:.7rem;';
$tileStyle = 'width:1.75rem;height:1.75rem;';

$isAdmin = !empty($isSiteAdmin) || !empty($me['Role']['perm_admin']);
$isOwner = isset($me['id'], $user['id']) && (int)$me['id'] === (int)$user['id'];
// Same gate as the actions card, plus what the pin action itself needs.
$canPin = ($isAdmin || $isOwner) && !empty($me['Role']['perm_auth']);
$userUrl = $isAdmin
    ? $baseurl . '/admin/users/view/' . (int)($user['id'] ?? 0)
    : ($isOwner ? $baseurl . '/users/view/me' : null);

// Expiration
$expiration = (int)($key['expiration'] ?? 0);
if ($expiration === 0) {
    $expiry = ['fas fa-infinity', 'bg-success-subtle text-success-emphasis', __('Never expires'), __('Valid until revoked')];
} elseif ($expiration <= time()) {
    $expiry = ['fas fa-hourglass-end', 'bg-danger-subtle text-danger-emphasis', __('Expired'), date('Y-m-d H:i', $expiration)];
} else {
    $days = (int)ceil(($expiration - time()) / 86400);
    $expiry = [
        'fas fa-hourglass-half',
        $days <= 7 ? 'bg-warning-subtle text-warning-emphasis' : 'bg-success-subtle text-success-emphasis',
        __n('Expires in %s day', 'Expires in %s days', $days, $days),
        date('Y-m-d H:i', $expiration),
    ];
}

$tiles = [
    $expiry,
    !empty($key['read_only'])
        ? ['fas fa-lock', 'bg-warning-subtle text-warning-emphasis', __('Read only'), __('Can query, cannot change anything')]
        : ['fas fa-lock-open', 'bg-body-secondary text-body-secondary', __('Read and write'), __('Acts with all of its user\'s rights')],
];
if (isset($keyUsage)) {
    $tiles[] = !empty($lastUsed)
        ? ['fas fa-clock-rotate-left', 'bg-primary-subtle text-primary-emphasis', $this->Time->time($lastUsed), __('Last used')]
        : ['fas fa-clock-rotate-left', 'bg-body-secondary text-body-secondary', __('Not used yet'), __('Last used')];
}

// Usage over the last 30 days, oldest first
$usageDays = [];
$usageTotal = 0;
if (isset($keyUsage) && is_array($keyUsage)) {
    for ($i = 29; $i >= 0; $i--) {
        $day = date('Y-m-d', strtotime("-$i days"));
        $count = (int)($keyUsage[$day] ?? 0);
        $usageDays[$day] = $count;
        $usageTotal += $count;
    }
}
$usagePeak = max(array_merge([1], array_values($usageDays)));

$allowed = $key['allowed_ips'] ?? null;
$allowed = is_array($allowed) ? array_values(array_filter($allowed, 'strlen')) : [];
$seenIps = $key['unique_ips'] ?? [];
$seenIps = is_array($seenIps) ? array_values(array_filter($seenIps, 'strlen')) : [];
$showSeen = !Configure::read('MISP.disable_seen_ips_authkeys');
?>
<div class="card mb-3 shadow-sm">
    <div class="card-body py-2 d-flex flex-column gap-3">

        <div>
            <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>">
                <i class="fas fa-key text-warning me-1"></i><?= __('Auth key') ?>
            </div>
            <div class="row row-cols-1 row-cols-sm-2 row-cols-xl-4 g-2">
                <div class="col">
                    <div class="d-flex align-items-center gap-2 min-w-0">
                        <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary text-body-secondary" style="<?= $tileStyle ?>">
                            <i class="fas fa-user"></i>
                        </span>
                        <div class="min-w-0">
                            <?php if ($userUrl): ?>
                                <a class="d-block fw-semibold lh-sm text-truncate text-decoration-none" href="<?= h($userUrl) ?>"
                                   title="<?= h($user['email'] ?? '') ?>"><?= h($user['email'] ?? $user['id'] ?? '') ?></a>
                            <?php else: ?>
                                <div class="fw-semibold lh-sm text-truncate"><?= h($user['email'] ?? '') ?></div>
                            <?php endif; ?>
                            <div class="small text-body-secondary"><?= __('Belongs to') ?></div>
                        </div>
                    </div>
                </div>
                <?php foreach ($tiles as $tile): ?>
                    <div class="col">
                        <div class="d-flex align-items-center gap-2 min-w-0">
                            <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 <?= $tile[1] ?>" style="<?= $tileStyle ?>">
                                <i class="<?= h($tile[0]) ?>"></i>
                            </span>
                            <div class="min-w-0">
                                <div class="fw-semibold lh-sm text-truncate"><?= strpos($tile[2], '<time') === 0 ? $tile[2] : h($tile[2]) ?></div>
                                <div class="small text-body-secondary text-truncate"><?= h($tile[3]) ?></div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <?php if (!empty($usageDays)): ?>
            <div>
                <div class="d-flex align-items-center justify-content-between flex-wrap gap-2 mb-1">
                    <span class="<?= $labelClass ?>" style="<?= $labelStyle ?>"><?= __('Usage, last 30 days') ?></span>
                    <span class="small text-body-secondary"><?= h(__n('%s request', '%s requests', $usageTotal, number_format($usageTotal, 0, ',', ' '))) ?></span>
                </div>
                <svg viewBox="0 0 300 40" preserveAspectRatio="none" class="d-block w-100 text-primary" style="height:3rem;"
                     role="img" aria-label="<?= h(__('Requests per day over the last 30 days')) ?>">
                    <?php $x = 0; foreach ($usageDays as $day => $count): ?>
                        <?php $height = $count === 0 ? 1 : max(2, round(38 * $count / $usagePeak, 1)); ?>
                        <rect x="<?= $x * 10 + 1 ?>" y="<?= 40 - $height ?>" width="8" height="<?= $height ?>" rx="1"
                              fill="currentColor" opacity="<?= $count === 0 ? '.2' : '.85' ?>">
                            <title><?= h($day) ?> · <?= h(__n('%s request', '%s requests', $count, $count)) ?></title>
                        </rect>
                    <?php $x++; endforeach; ?>
                </svg>
                <div class="d-flex justify-content-between small text-body-secondary">
                    <span><?= h(array_key_first($usageDays)) ?></span><span><?= __('Today') ?></span>
                </div>
            </div>
        <?php endif; ?>

        <div class="row g-3">
            <div class="col-md">
                <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Allowed IPs') ?></div>
                <?php if (empty($allowed)): ?>
                    <span class="small text-body-secondary"><i class="fas fa-globe me-1 opacity-50"></i><?= __('Any address') ?></span>
                <?php else: ?>
                    <div class="d-flex flex-wrap gap-1">
                        <?php foreach ($allowed as $ip): ?>
                            <span class="badge rounded-pill bg-success-subtle text-success-emphasis border border-success-subtle fw-normal font-monospace">
                                <i class="fas fa-shield-halved me-1 opacity-75"></i><?= h($ip) ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>
            <?php if ($showSeen): ?>
                <div class="col-md">
                    <div class="<?= $labelClass ?> mb-1" style="<?= $labelStyle ?>"><?= __('Seen from') ?></div>
                    <?php if (empty($seenIps)): ?>
                        <span class="small text-body-secondary fst-italic"><?= __('No address recorded yet') ?></span>
                    <?php else: ?>
                        <div class="d-flex flex-wrap gap-1">
                            <?php foreach ($seenIps as $i => $ip): ?>
                                <?php $pinned = $allowed === [$ip]; ?>
                                <span class="d-inline-flex align-items-stretch border rounded-pill bg-body-tertiary font-monospace overflow-hidden small">
                                    <span class="px-2 py-1"><?= h($ip) ?></span>
                                    <?php if ($canPin && !$pinned): ?>
                                        <span class="vr my-1"></span>
                                        <button type="button" class="btn btn-sm btn-link text-decoration-none px-2 py-0"
                                                title="<?= h(__('Only allow this address')) ?>" aria-label="<?= h(__('Only allow this address')) ?>"
                                                data-pin-ip="<?= h($ip) ?>" data-pin-target="authkey-pin-<?= $keyId ?>-<?= (int)$i ?>">
                                            <i class="fas fa-thumbtack"></i>
                                        </button>
                                        <?= $this->Form->postLink('', $baseurl . '/auth_keys/pin/' . $keyId, [
                                            'id' => 'authkey-pin-' . $keyId . '-' . (int)$i,
                                            'class' => 'd-none',
                                            'data' => ['ip' => $ip],
                                        ]) ?>
                                    <?php elseif ($pinned): ?>
                                        <span class="vr my-1"></span>
                                        <span class="px-2 py-1 text-success" title="<?= h(__('The only allowed address')) ?>"><i class="fas fa-thumbtack"></i></span>
                                    <?php endif; ?>
                                </span>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>

    </div>
</div>

<?php if ($canPin && !empty($seenIps)): ?>
<script>
(function () {
    document.querySelectorAll('[data-pin-ip]:not([data-pin-bound])').forEach(function (button) {
        button.setAttribute('data-pin-bound', '');
        button.addEventListener('click', function () {
            var ip = button.dataset.pinIp;
            var target = document.getElementById(button.dataset.pinTarget);
            if (!target || typeof showConfirmModal !== 'function') {
                return;
            }
            var code = document.createElement('code');
            code.textContent = ip;
            showConfirmModal({
                title: <?= json_encode(__('Restrict this key to one address')) ?>,
                body: <?= json_encode(__('The key will only be accepted from')) ?> + ' ' + code.outerHTML + '. '
                    + <?= json_encode(__('Any other allowed address is replaced.')) ?>,
                confirmLabel: <?= json_encode(__('Pin address')) ?>,
                confirmClass: 'btn-warning',
                cancelLabel: <?= json_encode(__('Cancel')) ?>,
                onConfirm: function () { target.click(); }
            });
        });
    });
})();
</script>
<?php endif; ?>
