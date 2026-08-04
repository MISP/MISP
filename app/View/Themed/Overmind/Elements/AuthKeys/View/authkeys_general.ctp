<?php
$a    = $data['AuthKey'];
$user = $data['User'] ?? [];

$field = function ($label, $valueHtml, $cols = 4) {
    return sprintf(
        '<div class="col-md-%d mb-3">
            <div class="text-muted small text-uppercase fw-bold mb-1">%s</div>
            <div class="fw-semibold">%s</div>
        </div>',
        (int)$cols,
        h($label),
        $valueHtml
    );
};

// Expiration badge
$exp = (int)($a['expiration'] ?? 0);
if ($exp === 0) {
    $expHtml = '<span class="badge text-bg-success">' . __('Indefinite') . '</span>';
} elseif ($exp <= time()) {
    $expHtml = '<span class="badge text-bg-danger">' . __('Expired') . ' (' . h(date('Y-m-d', $exp)) . ')</span>';
} else {
    $expHtml = '<span class="badge text-bg-success">' . h(date('Y-m-d H:i:s', $exp)) . '</span>';
}

// Allowed IPs
$allowed = $a['allowed_ips'] ?? null;
if (is_array($allowed) && !empty($allowed)) {
    $allowedHtml = implode(' ', array_map(function ($ip) {
        return '<span class="badge text-bg-light border font-monospace">' . h($ip) . '</span>';
    }, $allowed));
} else {
    $allowedHtml = '<span class="text-muted">' . __('All') . '</span>';
}

// Seen IPs — prefer the usage-derived list, fall back to the stored one
$seenIps = isset($uniqueIps) && is_array($uniqueIps) ? $uniqueIps : ($a['unique_ips'] ?? []);
$seenIpsHtml = empty($seenIps)
    ? '<span class="text-muted">&mdash;</span>'
    : implode(' ', array_map(function ($ip) {
        return '<span class="badge text-bg-light border font-monospace">' . h($ip) . '</span>';
    }, (array)$seenIps));
?>

<div class="card mb-3 shadow-sm">
    <div class="card-body p-4">

        <!-- AUTH KEY -->
        <div class="mb-4">
            <div class="text-muted small text-uppercase fw-bold mb-1"><?= __('Auth Key') ?></div>
            <div class="fs-5 font-monospace">
                <?= h($a['authkey_start'] ?? '') ?><span class="text-muted"><?= str_repeat('&bull;', 10) ?></span><?= h($a['authkey_end'] ?? '') ?>
            </div>
            <?php if (!empty($a['comment'])): ?>
                <div class="card card-link-item bg-light mt-2">
                    <div class="card-body p-1">
                        <i class="fa fa-comment"></i> <span><?= h($a['comment']) ?></span>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <div class="row g-0">
            <?= $field(__('ID'), '<span class="bg-light rounded px-2 py-1">' . h($a['id']) . '</span>') ?>

            <?php if (!empty($a['uuid'])): ?>
                <?= $field(__('UUID'), '<span class="font-monospace">' . h($a['uuid']) . '</span>', 8) ?>
            <?php endif; ?>

            <?php if (!empty($user)): ?>
                <?= $field(__('User'), sprintf(
                    '<a href="%s/users/view/%s">%s</a>',
                    h($baseurl),
                    h($user['id']),
                    h($user['email'] ?? $user['id'])
                )) ?>
            <?php endif; ?>

            <?= $field(__('Created'), !empty($a['created'])
                ? $this->Time->time($a['created'])
                : __('N/A')) ?>

            <?= $field(__('Expiration'), $expHtml) ?>

            <?= $field(__('Read only'), $this->element('genericElementsBS5/Badges/boolean', [
                'boolean' => !empty($a['read_only']),
                'full' => true,
                'true' => __('Yes'), 'false' => __('No'),
                'trueColor' => 'warning', 'falseColor' => 'secondary',
                'trueIcon' => 'fa-lock', 'falseIcon' => 'fa-lock-open',
            ])) ?>

            <?php if (isset($keyUsage)): ?>
                <?= $field(__('Last used'), !empty($lastUsed)
                    ? $this->Time->time($lastUsed)
                    : '<span class="text-muted">' . __('Not used yet') . '</span>') ?>
            <?php endif; ?>
        </div>

        <hr>

        <div class="text-muted small text-uppercase fw-bold mb-2"><?= __('Allowed IPs') ?></div>
        <div class="mb-3"><?= $allowedHtml ?></div>

        <?php if (!Configure::read('MISP.disable_seen_ips_authkeys')): ?>
            <div class="text-muted small text-uppercase fw-bold mb-2"><?= __('Seen IPs') ?></div>
            <div><?= $seenIpsHtml ?></div>
        <?php endif; ?>

    </div>
</div>
