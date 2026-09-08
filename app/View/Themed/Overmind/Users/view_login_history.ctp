<?php
/**
 * User login history
 * Renders the login sessions entry where each of them is a distinct login profile 
 * (platform + browser + location) seen over a time window, with a trust status and — for
 * unrecognised sessions 
 */
$isAjax = $this->request->is('ajax');

// Map the free-form trust status ('trusted', 'malicious', 'likely trusted',

$statusMeta = function ($status) {
    $status = (string)$status;
    $likely = str_contains($status, 'likely');
    if (str_contains($status, 'malicious')) {
        return [
            'color' => $likely ? 'warning' : 'danger',
            'icon'  => $likely ? 'triangle-exclamation' : 'bug',
            'label' => $likely ? __('Likely malicious') : __('Malicious'),
        ];
    }
    if (str_contains($status, 'trusted')) {
        return [
            'color' => $likely ? 'info' : 'success',
            'icon'  => $likely ? 'shield' : 'shield-halved',
            'label' => $likely ? __('Likely trusted') : __('Trusted'),
        ];
    }
    return ['color' => 'dark', 'icon' => 'circle-question', 'label' => __('Unknown')];
};


$platformIcon = function ($platform) {
    $p = strtolower((string)$platform);
    if (str_contains($p, 'win')) return 'fab fa-windows';
    if (str_contains($p, 'mac') || str_contains($p, 'ios') || str_contains($p, 'apple')) return 'fab fa-apple';
    if (str_contains($p, 'android')) return 'fab fa-android';
    if (str_contains($p, 'linux') || str_contains($p, 'ubuntu')) return 'fab fa-linux';
    return 'fas fa-display';
};
$browserIcon = function ($browser) {
    $b = strtolower((string)$browser);
    $map = [
        'chrome'   => 'fab fa-chrome',
        'firefox'  => 'fab fa-firefox-browser',
        'safari'   => 'fab fa-safari',
        'edge'     => 'fab fa-edge',
        'opera'    => 'fab fa-opera',
        'explorer' => 'fab fa-internet-explorer',
    ];
    foreach ($map as $needle => $icon) {
        if (str_contains($b, $needle)) return $icon;
    }
    return 'fas fa-globe';
};

$profilesUrl = sprintf('%s/userLoginProfiles/index/%s', $baseurl, h($user_id));

if (!$isAjax) {
    $this->set('headerTitle', __('Login history'));
    $this->set('headerDescription', __('Recent authentication sessions grouped by device, browser and location. Review any session you don\'t recognise and flag it if it looks suspicious.'));
    $this->set('headerActions', [
        [
            'type'  => 'navigate',
            'label' => __('Review login profiles'),
            'icon'  => 'fingerprint',
            'url'   => $profilesUrl,
        ],
    ]);
}
?>
<div class="container-fluid pb-4">
    <?php if (empty($data)): ?>
        <div class="card shadow-sm">
            <div class="card-body text-center text-muted py-5">
                <i class="fas fa-right-to-bracket fa-2x mb-3 opacity-50"></i>
                <div class="fw-semibold"><?= __('No login history available') ?></div>
            </div>
        </div>
    <?php else: ?>
        <div class="row g-3">
            <?php foreach ($data as $entry):
                $meta = $statusMeta($entry['status']);
                $needsReview = ('unknown' === $entry['status'])
                    || str_contains((string)$entry['status'], 'likely');

                // Parse the "web:login (3x) API:failed (1x)" summary into badges.
                $activity = [];
                if (!empty($entry['actions']) && preg_match_all('/(\S+)\s+\((\d+)x\)/', $entry['actions'], $matches, PREG_SET_ORDER)) {
                    foreach ($matches as $a) {
                        $activity[] = [
                            'label'  => $a[1],
                            'count'  => (int)$a[2],
                            'failed' => str_contains(strtolower($a[1]), 'fail'),
                        ];
                    }
                }
            ?>
                <div class="col-12 col-md-6 col-xl-4">
                    <div class="card h-100 shadow-sm border-top border-4 border-<?= h($meta['color']) ?>">

                        <!-- HEADER: device + trust status -->
                        <div class="card-header bg-transparent d-flex align-items-center justify-content-between gap-2">
                            <div class="d-flex align-items-center gap-2" style="min-width:0;">
                                <i class="<?= h($platformIcon($entry['platform'])) ?> text-muted" style="font-size:1.3rem;"></i>
                                <i class="<?= h($browserIcon($entry['browser'])) ?> text-muted" style="font-size:1.3rem;"></i>
                                <span class="fw-semibold text-truncate">
                                    <?= h($entry['platform']) ?> &middot; <?= h($entry['browser']) ?>
                                </span>
                            </div>
                            <span class="badge rounded-pill text-bg-<?= h($meta['color']) ?> flex-shrink-0">
                                <i class="fas fa-<?= h($meta['icon']) ?> me-1"></i><?= h($meta['label']) ?>
                            </span>
                        </div>

                        <div class="card-body d-flex flex-column gap-3">

                            <!-- Location -->
                            <div class="d-flex align-items-center gap-2">
                                <?php $flag = $this->Icon->countryFlag($entry['region']); ?>
                                <?= $flag ?: '<i class="fas fa-location-dot text-muted"></i>' ?>
                                <span class="fw-semibold"><?= h($entry['region']) ?: __('Unknown region') ?></span>
                                <?php if (!empty($entry['ip'])): ?>
                                    <span class="badge text-bg-light border font-monospace ms-auto"><?= h($entry['ip']) ?></span>
                                <?php endif; ?>
                            </div>

                            <!-- Activity summary -->
                            <?php if (!empty($activity)): ?>
                                <div>
                                    <div class="text-muted text-uppercase fw-bold mb-1" style="font-size:.62rem; letter-spacing:.07em;">
                                        <?= __('Activity') ?>
                                    </div>
                                    <div class="d-flex flex-wrap gap-1">
                                        <?php foreach ($activity as $a): ?>
                                            <span class="badge rounded-pill <?= $a['failed'] ? 'text-bg-danger' : 'text-bg-light border' ?>">
                                                <?= h($a['label']) ?><span class="opacity-75 ms-1">&times;<?= h($a['count']) ?></span>
                                            </span>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <!-- Seen window -->
                            <div class="d-flex align-items-center gap-2 text-muted small mt-auto">
                                <i class="fas fa-clock"></i>
                                <span><?= h($entry['first_seen']) ?></span>
                                <i class="fas fa-arrow-right-long opacity-50"></i>
                                <span><?= h($entry['last_seen']) ?></span>
                            </div>
                        </div>

                        <!-- FOOTER: review actions for unrecognised sessions -->
                        <?php if ($needsReview): $eid = (int)$entry['id']; ?>
                            <div class="card-footer bg-transparent d-flex gap-2">
                                <button type="button"
                                        class="btn btn-sm btn-success-subtle text-success flex-fill fw-semibold"
                                        onclick="loginHistoryReview('trust', <?= $eid ?>)">
                                    <i class="fas fa-user-check me-1"></i><?= __('This was me') ?>
                                </button>
                                <button type="button"
                                        class="btn btn-sm btn-danger-subtle text-danger flex-fill fw-semibold"
                                        onclick="loginHistoryReview('malicious', <?= $eid ?>)">
                                    <i class="fas fa-bug me-1"></i><?= __('Report') ?>
                                </button>
                            </div>
                            <?php
                                // Hidden secure POST triggers — CakePHP mints the CSRF
                                // token here. The confirmation modal clicks these once
                                // the user confirms (see loginHistoryReview() below).
                                echo $this->Form->postLink('', ['controller' => 'userLoginProfiles', 'action' => 'trust', $eid], [
                                    'id' => 'login-history-trust-' . $eid,
                                    'class' => 'd-none',
                                    'escape' => false,
                                ]);
                                echo $this->Form->postLink('', ['controller' => 'userLoginProfiles', 'action' => 'malicious', $eid], [
                                    'id' => 'login-history-malicious-' . $eid,
                                    'class' => 'd-none',
                                    'escape' => false,
                                ]);
                            ?>
                        <?php endif; ?>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if ($isAjax): // full page exposes this via a header action instead ?>
        <div class="mt-3">
            <a href="<?= h($profilesUrl) ?>" class="btn btn-outline-dark fw-semibold">
                <i class="fas fa-fingerprint me-1"></i><?= __('Review login profiles') ?>
            </a>
        </div>
    <?php endif; ?>
</div>

<script>

function loginHistoryReview(action, id) {
    var configs = {
        trust: {
            title:        <?= json_encode(__('Trust this device')) ?>,
            icon:         'fa-user-check text-success',
            message:      <?= json_encode(__('Are you sure you want to mark this device as trusted?')) ?>,
            confirmLabel: <?= json_encode(__('This was me')) ?>,
            confirmClass: 'btn-success',
        },
        malicious: {
            title:        <?= json_encode(__('Report as malicious')) ?>,
            icon:         'fa-bug text-danger',
            message:      <?= json_encode(__('Was this connection suspicious or malicious? If yes, you will be forced to change your password.')) ?>,
            confirmLabel: <?= json_encode(__('Report malicious')) ?>,
            confirmClass: 'btn-danger',
        },
    };
    var cfg = configs[action];
    if (!cfg || typeof showConfirmModal !== 'function') {
        return;
    }

    var body =
        '<div class="d-flex align-items-start gap-3">' +
            '<i class="fas ' + cfg.icon + ' fa-2x mt-1"></i>' +
            '<p class="mb-0 text-muted small">' + cfg.message + '</p>' +
        '</div>';

    showConfirmModal({
        title:        cfg.title,
        body:         body,
        confirmLabel: cfg.confirmLabel,
        confirmClass: cfg.confirmClass,
        cancelLabel:  <?= json_encode(__('Cancel')) ?>,
        onConfirm:    function () {
            var trigger = document.getElementById('login-history-' + action + '-' + id);
            if (trigger) { trigger.click(); }
        },
    });
}
</script>
