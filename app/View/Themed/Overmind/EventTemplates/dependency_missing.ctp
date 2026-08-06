<?php

$fixCommand = 'cd ' . rtrim(APP, DS) . ' && composer install';

/*
 * Containerised installs need a different recipe (no composer binary in the
 * image, vendor lives in the image layer, root shell), so the fix card offers
 * both and preselects the one that matches this host. `/.dockerenv` is the
 * reliable marker — the /proc/1/cgroup trick returns a bare "0::/" under
 * cgroup v2, so it is only a fallback for older hosts.
 */
$isDocker = file_exists('/.dockerenv');
if (!$isDocker && is_readable('/proc/1/cgroup')) {
    $isDocker = strpos((string)@file_get_contents('/proc/1/cgroup'), 'docker') !== false;
}
$containerRef = gethostname() ?: 'misp-core';

$dockerSteps = [
    [
        'label' => __('Open a root shell in the MISP container.'),
        'cmd' => 'docker exec -it ' . $containerRef . ' bash',
        'hint' => __('%s is this container\'s id. With docker compose, the service name works too — usually %s.',
            '<code>' . h($containerRef) . '</code>', '<code>misp-core</code>'),
    ],
    [
        'label' => __('The image ships no composer binary — fetch one.'),
        'cmd' => 'php -r "copy(\'https://getcomposer.org/installer\', \'/tmp/composer-setup.php\');"'
            . ' && php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer',
    ],
    [
        'label' => __('Install only the missing packages.'),
        'cmd' => 'cd ' . rtrim(APP, DS) . ' && COMPOSER_ALLOW_SUPERUSER=1 composer update -W '
            . implode(' ', $missing),
    ],
    [
        'label' => __('Hand the files back to the web-server user.'),
        'cmd' => 'chown -R www-data:www-data ' . rtrim(APP, DS) . '/Vendor',
    ],
];

/** One command in a bordered box with a copy button. */
$cmdBox = function ($command) {
    ?>
    <div class="border rounded bg-body-tertiary px-3 py-2 d-flex
                align-items-center justify-content-between gap-2">
        <code class="text-body text-break" style="font-size:.78rem;"><?= h($command) ?></code>
        <button type="button" class="btn btn-sm btn-outline-secondary flex-shrink-0"
                onclick="copyValueToClipboard(<?= h(json_encode($command)) ?>, <?= h(json_encode(__('Command copied'))) ?>)">
            <i class="fas fa-copy"></i>
        </button>
    </div>
    <?php
};

$this->set('headerTitle', __('Event Templates'));
$this->set('headerDescription', __('The event-templating feature is disabled on this instance until its PHP dependencies are installed.'));
$this->set('headerActions', [
    [
        'type' => 'navigate',
        'label' => __('Back to events'),
        'icon' => 'arrow-left',
        'url' => $baseurl . '/events/index',
    ],
]);
?>
<div class="container-fluid px-3 px-lg-4 pb-4">

    <div class="alert alert-warning d-flex align-items-start gap-3 shadow-sm" role="alert">
        <i class="fas fa-plug-circle-exclamation flex-shrink-0 mt-1"
           style="font-size:1.5rem; opacity:.7;"></i>
        <div>
            <div class="fw-bold mb-1"><?= __('Event templating is unavailable') ?></div>
            <div style="font-size:.85rem;">
                <?= __('Every event-template page, and the "From template" shortcut on the Events index, stays disabled until an administrator installs the packages listed below.') ?>
            </div>
        </div>
    </div>

    <div class="row g-3">

        <div class="col-12 col-lg-5">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-warning-subtle fw-semibold d-flex
                            align-items-center justify-content-between">
                    <span>
                        <i class="fas fa-cube me-1"></i><?= __('Missing PHP package(s)') ?>
                    </span>
                    <span class="badge rounded-pill text-bg-warning">
                        <?= (int)count($missing) ?>
                    </span>
                </div>
                <ul class="list-group list-group-flush">
                    <?php foreach ($missing as $package): ?>
                        <li class="list-group-item d-flex align-items-center gap-2 py-2">
                            <i class="fas fa-circle-xmark text-danger" style="font-size:.75rem;"></i>
                            <code class="text-body"><?= h($package) ?></code>
                        </li>
                    <?php endforeach; ?>
                </ul>
                <div class="card-footer bg-transparent text-muted" style="font-size:.75rem;">
                    <?= __('Declared in %s — not loadable in this PHP runtime.',
                        '<code>app/composer.json</code>') ?>
                </div>
            </div>
        </div>

        <div class="col-12 col-lg-7">
            <div class="card shadow-sm h-100">
                <div class="card-header bg-transparent pb-0">
                    <div class="d-flex align-items-center justify-content-between mb-2">
                        <span class="fw-semibold">
                            <i class="fas fa-screwdriver-wrench me-1"></i><?= __('How to fix it') ?>
                        </span>
                        <?php if ($isDocker): ?>
                            <span class="badge rounded-pill text-bg-info">
                                <i class="fab fa-docker me-1"></i><?= __('Docker detected') ?>
                            </span>
                        <?php endif; ?>
                    </div>
                    <ul class="nav nav-tabs card-header-tabs" role="tablist">
                        <?php
                        // Detected environment first: the tab that actually applies
                        // should be the one the eye lands on, not just the active one.
                        $tabs = [
                            'docker' => ['<i class="fab fa-docker me-1"></i>' . __('Docker'), $isDocker],
                            'host' => ['<i class="fas fa-server me-1"></i>' . __('Standard install'), !$isDocker],
                        ];
                        if (!$isDocker) {
                            $tabs = array_reverse($tabs, true);
                        }
                        foreach ($tabs as $key => [$label, $active]):
                        ?>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link<?= $active ? ' active' : '' ?>"
                                        type="button" role="tab"
                                        data-bs-toggle="tab"
                                        data-bs-target="#fixTab<?= h(ucfirst($key)) ?>">
                                    <?= $label ?>
                                </button>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
                <div class="card-body">
                    <div class="tab-content">

                        <!-- ── DOCKER ──────────────────────────────────── -->
                        <div class="tab-pane fade<?= $isDocker ? ' show active' : '' ?>"
                             id="fixTabDocker" role="tabpanel">
                            <p class="text-muted" style="font-size:.85rem;">
                                <?= __('The container image bakes its PHP dependencies in at build time, so a newer MISP checkout can need packages the running image does not have. Install them inside the container:') ?>
                            </p>

                            <ol class="ps-3 mb-3" style="font-size:.85rem;">
                                <?php foreach ($dockerSteps as $step): ?>
                                    <li class="mb-2">
                                        <div class="mb-1"><?= h($step['label']) ?></div>
                                        <?php $cmdBox($step['cmd']); ?>
                                        <?php if (!empty($step['hint'])): ?>
                                            <div class="text-muted mt-1" style="font-size:.72rem;">
                                                <?= $step['hint'] ?>
                                            </div>
                                        <?php endif; ?>
                                    </li>
                                <?php endforeach; ?>
                                <li><?= __('Reload this page — the feature comes back on its own.') ?></li>
                            </ol>

                            <div class="alert alert-warning py-2 mb-2" role="alert"
                                 style="font-size:.78rem;">
                                <i class="fas fa-triangle-exclamation me-1"></i>
                                <?= __('Do not run a bare %s or add %s. If your compose file bind-mounts %s from a source checkout, it no longer matches the image\'s lock file and composer will happily REMOVE the packages the image added on top (aws-sdk, elasticsearch, openid-connect, phpseclib, DebugKit). Updating the named packages only, as above, leaves the rest alone.',
                                    '<code>composer install</code>', '<code>--no-dev</code>',
                                    '<code>app/composer.json</code>') ?>
                            </div>

                            <div class="alert alert-light border py-2 mb-0" role="alert"
                                 style="font-size:.78rem;">
                                <i class="fas fa-circle-info me-1 text-primary"></i>
                                <?= __('This writes to the container\'s writable layer: a %s or an image rebuild wipes it. Make it stick by rebuilding the image from the current checkout, or by adding the install to your startup customisation script.',
                                    '<code>docker compose down</code>') ?>
                            </div>
                        </div>

                        <!-- ── STANDARD HOST ───────────────────────────── -->
                        <div class="tab-pane fade<?= $isDocker ? '' : ' show active' ?>"
                             id="fixTabHost" role="tabpanel">
                            <p class="text-muted" style="font-size:.85rem;">
                                <?= __('MISP\'s standard upgrade flow (git pull + %s) does not install composer packages, so they have to be pulled in by hand after an upgrade.',
                                    '<code>cake Admin runUpdates</code>') ?>
                            </p>

                            <ol class="mb-3 ps-3" style="font-size:.85rem;">
                                <li class="mb-1"><?= __('Open a shell on the MISP host.') ?></li>
                                <li class="mb-1"><?= __('Run the command below as the web-server user.') ?></li>
                                <li><?= __('Reload this page — the feature comes back on its own.') ?></li>
                            </ol>

                            <?php $cmdBox($fixCommand); ?>
                        </div>

                    </div>

                    <?php if (!$isSiteAdmin): ?>
                        <div class="alert alert-light border mt-3 mb-0" role="alert"
                             style="font-size:.8rem;">
                            <i class="fas fa-circle-info me-1 text-primary"></i>
                            <?= __('You do not have the privileges to fix this yourself — contact your MISP administrator.') ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

    </div>
</div>
