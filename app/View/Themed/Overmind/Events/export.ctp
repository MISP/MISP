<?php
/*
 * events/export — cached exports & text signature downloads.
 *
 * Two independent blocks:
 *   1. Cached exports  — one row per export format, generated in the
 *      background per organisation. Only populated when
 *      MISP.background_jobs is on and MISP.disable_cached_exports is off,
 *      otherwise $export_types comes back empty from the controller.
 *   2. Text signatures — one chip per attribute type (~200 of them), hence
 *      the live filter. The target URL differs between the cached and the
 *      on-the-fly (restSearch) mode.
 *
 * Row state is carried to the client through $exportJobs rather than a
 * per-row inline <script>, so a single boot block owns the polling.
 */

$background = !empty(Configure::read('MISP.background_jobs'))
    && empty(Configure::read('MISP.disable_cached_exports'));

/* Accent + glyph per export format. --h feeds the hsl() ramp in .ex-icon. */
$formatStyles = [
    'json'      => ['icon' => 'file-code',     'hue' => 205],
    'xml'       => ['icon' => 'file-code',     'hue' => 265],
    'csv_sig'   => ['icon' => 'file-csv',      'hue' => 145],
    'csv_all'   => ['icon' => 'file-csv',      'hue' => 165],
    'suricata'  => ['icon' => 'shield-halved', 'hue' => 15],
    'snort'     => ['icon' => 'shield-halved', 'hue' => 35],
    'bro'       => ['icon' => 'network-wired', 'hue' => 55],
    'stix'      => ['icon' => 'share-nodes',   'hue' => 300],
    'stix2'     => ['icon' => 'share-nodes',   'hue' => 320],
    'rpz'       => ['icon' => 'globe',         'hue' => 190],
    'text'      => ['icon' => 'file-lines',    'hue' => 225],
    'yara'      => ['icon' => 'bug',           'hue' => 85],
    'yara-json' => ['icon' => 'bug',           'hue' => 105],
];

/*
 * Cache freshness of one export type. `filesize` is only set by the
 * controller when the cached file is readable, `recommendation` is its
 * "should be regenerated" flag.
 */
$cacheState = function (array $type) {
    if (($type['lastModified'] ?? '') === 'No valid events') {
        return [
            'key' => 'empty',
            'label' => __('No valid events'),
            'class' => 'text-bg-secondary',
            'icon' => 'circle-minus',
        ];
    }
    if (!isset($type['filesize'])) {
        return [
            'key' => 'missing',
            'label' => __('Not cached'),
            'class' => 'text-bg-warning',
            'icon' => 'hourglass-half',
        ];
    }
    if (!empty($type['recommendation'])) {
        return [
            'key' => 'stale',
            'label' => __('Outdated'),
            'class' => 'text-bg-danger',
            'icon' => 'triangle-exclamation',
        ];
    }
    return [
        'key' => 'fresh',
        'label' => __('Up to date'),
        'class' => 'text-bg-success',
        'icon' => 'circle-check',
    ];
};

$stateCounts = ['fresh' => 0, 'stale' => 0, 'missing' => 0, 'empty' => 0];
foreach ($export_types as $type) {
    $stateCounts[$cacheState($type)['key']]++;
}

$headerTitle = __('Exports');
$headerDescription = __(
    'Download the data you have access to in the format your tooling '
    . 'expects — NIDS rules, STIX documents, raw JSON/XML or plain '
    . 'signature lists.'
);

$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);

// events/automation is gated on perm_auth, don't advertise a 403.
$this->set('headerActions', empty($me['Role']['perm_auth']) ? [] : [
    [
        'type' => 'navigate',
        'label' => __('Automation API'),
        'icon' => 'gears',
        'url' => $baseurl . '/events/automation',
        'title' => __('Query the same data programmatically'),
    ],
]);
?>

<?php if (Configure::read('MISP.disable_cached_exports', true)): ?>
<div class="ex-scope container-fluid pb-4">
    <div class="alert alert-danger d-flex align-items-start gap-3 shadow-sm mb-0"
            role="alert">
        <i class="fa-solid fa-triangle-exclamation fa-lg mt-1"></i>
        <div>
            <div class="fw-semibold"><?= __('Cached exports are disabled') ?></div>
            <p class="mb-0 small">
                <?= __('This instance has MISP.disable_cached_exports turned on. '
                    . 'Ask a site administrator to enable it, or query the data '
                    . 'through the restSearch API instead.') ?>
            </p>
        </div>
    </div>
</div>
<?php return; endif; ?>

<div class="ex-scope container-fluid pb-4">

    <!-- ── what this page does ──────────────────────────────────────────── -->
    <div class="alert alert-light border d-flex align-items-start gap-3 shadow-sm mb-4">
        <i class="fa-solid fa-circle-info fa-lg mt-1 text-primary"></i>
        <div class="small mb-0">
            <?= __('Exports automatically generate signatures for intrusion detection '
                . 'systems. An attribute is only picked up when its <strong>IDS</strong> '
                . 'flag is set to yes.') ?>
            <br>
            <span class="text-secondary">
                <?= __('Signature generation is currently supported for network '
                    . 'indicators (IP addresses, domains, hostnames, user agents…) '
                    . 'and for hash lists built from the MD5/SHA1 values of file '
                    . 'artifacts. More attribute types are planned.') ?>
            </span>
        </div>
    </div>

    <!-- ══ CACHED EXPORTS ═══════════════════════════════════════════════ -->
    <div class="card shadow-sm mb-4">

        <div class="card-header bg-body-tertiary d-flex flex-wrap align-items-center gap-2 py-2">
            <i class="fa-solid fa-database text-secondary"></i>
            <span class="fw-semibold"><?= __('Cached exports') ?></span>
            <?php if (!empty($export_types)): ?>
                <span class="badge rounded-pill text-bg-secondary">
                    <?= count($export_types) ?>
                </span>
            <?php endif; ?>
            <span class="ms-auto small text-secondary d-none d-lg-inline">
                <?= __('Regenerated in the background, scoped to what your organisation can see.') ?>
            </span>
        </div>

        <?php if (empty($export_types)): ?>

            <div class="card-body">
                <div class="d-flex flex-column align-items-center text-secondary py-5">
                    <i class="fa-solid fa-inbox fa-2x mb-3 opacity-50"></i>
                    <div class="fw-semibold mb-1"><?= __('No cached export available') ?></div>
                    <p class="small text-center mb-0" style="max-width: 34rem;">
                        <?= __('Cached exports need the background workers to be enabled '
                            . '(MISP.background_jobs). Until then, use the signature lists '
                            . 'below or the restSearch API to pull data on demand.') ?>
                    </p>
                </div>
            </div>

        <?php else: ?>

            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover align-middle mb-0 ex-table">
                        <thead>
                            <tr>
                                <th class="text-uppercase small text-secondary fw-semibold"
                                    style="min-width: 11rem;"><?= __('Format') ?></th>
                                <th class="text-uppercase small text-secondary fw-semibold">
                                    <?= __('Description') ?></th>
                                <th class="text-uppercase small text-secondary fw-semibold"
                                    style="min-width: 12rem;"><?= __('Cache') ?></th>
                                <th class="text-uppercase small text-secondary fw-semibold text-end"
                                    style="min-width: 13rem;"><?= __('Actions') ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php
                        $i = 0;
                        $exportJobs = [];
                        foreach ($export_types as $k => $type):
                            $state = $cacheState($type);
                            $style = $formatStyles[$k]
                                ?? ['icon' => 'file-arrow-down', 'hue' => 210];
                            $exportJobs[] = [
                                'i' => $i,
                                'key' => $k,
                                'jobId' => (int)$type['job_id'],
                                'progress' => (int)$type['progress'],
                                'modified' => (string)$type['lastModified'],
                            ];
                            // Only swap the badge for a bar when the boot block
                            // below will actually poll this row.
                            $running = (int)$type['job_id'] !== -1
                                && (int)$type['progress'] > 0
                                && (int)$type['progress'] < 100
                                && $type['lastModified'] !== 'N/A';
                        ?>
                            <tr>

                                <!-- Format -->
                                <td>
                                    <div class="d-flex align-items-center gap-2">
                                        <span class="ex-icon" style="--h: <?= (int)$style['hue'] ?>;">
                                            <i class="fa-solid fa-<?= h($style['icon']) ?>"></i>
                                        </span>
                                        <span class="lh-sm">
                                            <span class="d-block fw-semibold"><?= h($type['type']) ?></span>
                                            <code class="small text-secondary"><?= h($type['extension']) ?></code>
                                        </span>
                                    </div>
                                </td>

                                <!-- Description -->
                                <td>
                                    <div class="small mb-1 ex-desc"><?= h($type['description']) ?></div>
                                    <div class="d-flex flex-wrap gap-1">
                                        <span class="ex-meta-chip">
                                            <i class="fa-solid fa-layer-group"></i>
                                            <?= h($type['scope']) ?>
                                        </span>
                                        <?php if (!empty($type['requiresPublished'])): ?>
                                            <span class="ex-meta-chip">
                                                <i class="fa-solid fa-tower-broadcast"></i>
                                                <?= __('Published only') ?>
                                            </span>
                                        <?php endif; ?>
                                        <?php if (!empty($type['params']['includeAttachments'])): ?>
                                            <?php $attachmentsOn = (bool)Configure::read('MISP.cached_attachments'); ?>
                                            <span class="ex-meta-chip <?= $attachmentsOn ? 'ex-meta-chip-on' : 'ex-meta-chip-off' ?>"
                                                    title="<?= h($attachmentsOn
                                                        ? __('Attachments are enabled on this instance')
                                                        : __('Attachments are disabled on this instance')) ?>">
                                                <i class="fa-solid fa-paperclip"></i>
                                                <?= $attachmentsOn
                                                    ? __('Attachments included')
                                                    : __('Attachments disabled') ?>
                                            </span>
                                        <?php endif; ?>
                                    </div>
                                </td>

                                <!-- Cache status + live progress -->
                                <td>
                                    <span id="exportBadge<?= $i ?>"
                                            class="badge rounded-pill <?= h($state['class']) ?><?= $running ? ' d-none' : '' ?>">
                                        <i class="fa-solid fa-<?= h($state['icon']) ?> me-1"></i>
                                        <?= h($state['label']) ?>
                                    </span>

                                    <div id="exportBarFrame<?= $i ?>"
                                            class="progress ex-progress<?= $running ? '' : ' d-none' ?>"
                                            role="progressbar"
                                            aria-valuemin="0" aria-valuemax="100"
                                            aria-valuenow="<?= (int)$type['progress'] ?>">
                                        <div id="exportBar<?= $i ?>"
                                                class="progress-bar progress-bar-striped progress-bar-animated"
                                                style="width: <?= (int)$type['progress'] ?>%;">
                                            <?= (int)$type['progress'] ?>%
                                        </div>
                                    </div>

                                    <?php
                                    // The badge already says "not cached" / "no
                                    // valid events", so don't echo the sentinel
                                    // twice. The span stays for the JS to fill.
                                    $metaText = in_array(
                                        $type['lastModified'],
                                        ['N/A', 'No valid events'],
                                        true
                                    ) ? '' : $type['lastModified'];
                                    ?>
                                    <div class="small text-secondary mt-1">
                                        <span id="exportMeta<?= $i ?>"><?= h($metaText) ?></span>
                                        <?php if (isset($type['filesize'])): ?>
                                            <span class="ex-dot">·</span>
                                            <span class="font-monospace"><?= h($type['filesize']) ?></span>
                                        <?php endif; ?>
                                    </div>
                                </td>

                                <!-- Actions -->
                                <td class="text-end">
                                    <div class="btn-group btn-group-sm" role="group">
                                        <?php if ($k === 'text'): ?>
                                            <a href="#exSignatures" class="btn btn-outline-secondary">
                                                <i class="fa-solid fa-list-check me-1"></i>
                                                <?= __('Pick a type') ?>
                                            </a>
                                        <?php else: ?>
                                            <?php $downloadable = isset($type['filesize']); ?>
                                            <a href="<?= h($baseurl . '/events/downloadExport/' . $k) ?>"
                                                    class="btn btn-outline-secondary<?= $downloadable ? '' : ' disabled' ?>"
                                                    <?= $downloadable ? '' : 'aria-disabled="true" tabindex="-1"' ?>
                                                    title="<?= h($downloadable
                                                        ? __('Download the cached file')
                                                        : __('Nothing cached yet, generate it first')) ?>">
                                                <i class="fa-solid fa-download me-1"></i>
                                                <?= __('Download') ?>
                                            </a>
                                        <?php endif; ?>
                                        <button type="button"
                                                id="exportGenerateBtn<?= $i ?>"
                                                class="btn btn-outline-primary"
                                                onclick="mispExportGenerate(<?= $i ?>, '<?= h($k) ?>')"
                                                <?= empty($type['recommendation']) ? 'disabled' : '' ?>
                                                title="<?= h(empty($type['recommendation'])
                                                    ? __('This cache is already up to date')
                                                    : __('Queue a background job to rebuild this cache')) ?>">
                                            <i class="fa-solid fa-rotate me-1"></i>
                                            <?= __('Generate') ?>
                                        </button>
                                    </div>
                                    <?php // CSRF-signed POST form for jobs/cache, submitted by fetch() ?>
                                    <div class="d-none" id="exportForm<?= $i ?>">
                                        <?= $this->Form->postLink(
                                            __('Generate'),
                                            ['controller' => 'jobs', 'action' => 'cache', $k]
                                        ) ?>
                                    </div>
                                </td>

                            </tr>
                        <?php
                            $i++;
                        endforeach;
                        ?>
                        </tbody>
                    </table>
                </div>
            </div>

        <?php endif; ?>

    </div>

    <!-- ══ TEXT SIGNATURE TYPES ═════════════════════════════════════════ -->
    <div class="card shadow-sm mb-0" id="exSignatures">

        <div class="card-header bg-body-tertiary d-flex flex-wrap align-items-center gap-2 py-2">
            <i class="fa-solid fa-file-lines text-secondary"></i>
            <span class="fw-semibold"><?= __('Text signature types') ?></span>
            <span class="badge rounded-pill text-bg-secondary"><?= count($sigTypes) ?></span>
            <div class="ms-auto d-flex align-items-center gap-2">
                <span id="exSigCounter" class="small text-secondary d-none d-md-inline"></span>
                <div class="input-group input-group-sm" style="max-width: 18rem;">
                    <span class="input-group-text bg-body">
                        <i class="fa-solid fa-magnifying-glass"></i>
                    </span>
                    <input type="search" id="exSigSearch" class="form-control"
                            placeholder="<?= h(__('Filter types…')) ?>"
                            autocomplete="off" spellcheck="false"
                            aria-label="<?= h(__('Filter signature types')) ?>">
                </div>
            </div>
        </div>

        <div class="card-body">
            <p class="small text-secondary">
                <?= __('One plain-text list per attribute type, built from published '
                    . 'events whose attributes are flagged for IDS. Useful to feed '
                    . 'forensic tooling looking for a specific artifact.') ?>
            </p>

            <div class="d-flex flex-wrap gap-1 ex-siglist" id="exSigList">
                <?php foreach ($sigTypes as $sigType): ?>
                    <?php
                    $sigUrl = $background
                        ? $baseurl . '/events/downloadExport/text/' . $sigType
                        : $baseurl . '/attributes/restSearch/returnFormat:text/type:'
                            . $sigType . '.json';
                    ?>
                    <a href="<?= h($sigUrl) ?>" class="ex-chip"
                            data-search="<?= h(strtolower($sigType)) ?>"><?= h($sigType) ?></a>
                <?php endforeach; ?>
            </div>

            <div class="text-center text-secondary py-4 d-none" id="exSigEmpty">
                <i class="fa-solid fa-magnifying-glass fa-2x mb-2 d-block opacity-50"></i>
                <?= __('No signature type matches your filter.') ?>
            </div>
        </div>

    </div>

</div>

<script>
(function () {
    'use strict';

    /* ── signature type live filter ──────────────────────────────────── */
    var search = document.getElementById('exSigSearch');
    var list = document.getElementById('exSigList');
    if (search && list) {
        var chips = Array.prototype.slice.call(list.querySelectorAll('.ex-chip'));
        var empty = document.getElementById('exSigEmpty');
        var counter = document.getElementById('exSigCounter');

        var applyFilter = function () {
            var needle = search.value.trim().toLowerCase();
            var shown = 0;
            chips.forEach(function (chip) {
                var hit = needle === '' || chip.dataset.search.indexOf(needle) !== -1;
                chip.classList.toggle('d-none', !hit);
                if (hit) {
                    shown++;
                }
            });
            list.classList.toggle('d-none', shown === 0);
            if (empty) {
                empty.classList.toggle('d-none', shown !== 0);
            }
            if (counter) {
                counter.textContent = needle === ''
                    ? ''
                    : shown + ' / ' + chips.length;
            }
        };

        search.addEventListener('input', applyFilter);
        applyFilter();
    }

    /* ── cached export jobs ──────────────────────────────────────────── */
    var jobs = <?= json_encode($exportJobs ?? [], JSON_UNESCAPED_SLASHES) ?>;
    if (!jobs.length) {
        return;
    }

    var POLL_MS = 3000;
    var timers = {};
    var labels = {
        fresh: <?= json_encode(__('Up to date')) ?>,
        justNow: <?= json_encode(__('0 seconds ago')) ?>,
        workerDown: <?= json_encode(__('Warning, the background worker is not responding!')) ?>
    };

    var el = function (id) { return document.getElementById(id); };

    var showProgress = function (i, percent) {
        var frame = el('exportBarFrame' + i);
        var bar = el('exportBar' + i);
        var badge = el('exportBadge' + i);
        if (!frame || !bar) {
            return;
        }
        if (badge) {
            badge.classList.add('d-none');
        }
        frame.classList.remove('d-none');
        frame.setAttribute('aria-valuenow', percent);
        bar.style.width = percent + '%';
        bar.textContent = percent + '%';
    };

    var stop = function (i) {
        if (timers[i]) {
            clearInterval(timers[i]);
            delete timers[i];
        }
    };

    var complete = function (i) {
        stop(i);
        var frame = el('exportBarFrame' + i);
        if (frame) {
            frame.classList.add('d-none');
        }
        var badge = el('exportBadge' + i);
        if (badge) {
            badge.className = 'badge rounded-pill text-bg-success';
            badge.innerHTML = '<i class="fa-solid fa-circle-check me-1"></i>'
                + labels.fresh;
        }
        var meta = el('exportMeta' + i);
        if (meta) {
            meta.textContent = labels.justNow;
        }
        var button = el('exportGenerateBtn' + i);
        if (button) {
            button.disabled = true;
        }
    };

    var poll = function (i, key) {
        fetch(baseurl + '/jobs/getProgress/cache_' + encodeURIComponent(key), {
            headers: {'Accept': 'application/json'}
        })
        .then(function (response) {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }
            return response.json();
        })
        .then(function (percent) {
            percent = parseInt(percent, 10);
            if (percent === -1) {
                stop(i);
                console.warn(labels.workerDown);
                return;
            }
            if (percent >= 100) {
                complete(i);
                return;
            }
            showProgress(i, Math.max(percent, 0));
        })
        .catch(function (error) {
            console.error('export progress:', error);
        });
    };

    var start = function (i, key) {
        if (timers[i]) {
            return;
        }
        timers[i] = setInterval(function () { poll(i, key); }, POLL_MS);
    };

    /*
     * The visible button is a plain <button>; the CSRF-signed form Cake
     * generated for jobs/cache lives hidden in the same cell and is what we
     * actually POST.
     */
    window.mispExportGenerate = function (i, key) {
        var button = el('exportGenerateBtn' + i);
        var holder = el('exportForm' + i);
        var form = holder ? holder.querySelector('form') : null;
        if (!button || !form) {
            return;
        }
        var original = button.innerHTML;
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-1"'
            + ' role="status" aria-hidden="true"></span>' + original.replace(/<[^>]*>/g, '').trim();

        fetch(form.getAttribute('action'), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: new URLSearchParams(new FormData(form)).toString()
        })
        .then(function (response) {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }
            return response.text();
        })
        .then(function () {
            button.innerHTML = original;
            showProgress(i, 1);
            start(i, key);
        })
        .catch(function (error) {
            console.error('export generate:', error);
            button.disabled = false;
            button.innerHTML = original;
        });
    };

    jobs.forEach(function (job) {
        if (job.jobId !== -1 && job.progress < 100 && job.modified !== 'N/A') {
            start(job.i, job.key);
        }
    });
}());
</script>
