<?php

$previewMaxFile = 262144;      // 256 KB — a logo is never this big
$previewBudget = 1572864;      // 1.5 MB of data URIs per render
$previewsSkipped = 0;

$svgAllowed = (bool)Configure::read('Security.enable_svg_logos');

$formatBytes = function ($bytes) {
    $bytes = (int)$bytes;
    if ($bytes < 1024) {
        return $bytes . ' B';
    }
    foreach (array('MB' => 1048576, 'KB' => 1024) as $unit => $scale) {
        if ($bytes >= $scale) {
            $value = $bytes / $scale;
            return number_format($value, $value >= 100 ? 0 : 1, ',', ' ') . ' ' . $unit;
        }
    }
    return $bytes . ' B';
};

$categoryMeta = array(
    'orgs' => array('icon' => 'building', 'accent' => '#0d6efd'),
    'img' => array('icon' => 'image', 'accent' => '#6f42c1'),
);

$confirmations = array();
$uid = 'fl' . dechex(mt_rand());
?>
<div class="ss-scope fl-scope" id="<?= h($uid) ?>">

    <?php foreach ($files as $type => $category): ?>
        <?php
        $meta = isset($categoryMeta[$type])
            ? $categoryMeta[$type]
            : array('icon' => 'folder-open', 'accent' => '#6c757d');

        $categoryFiles = !empty($category['files']) ? $category['files'] : array();
        $present = array();
        foreach ($categoryFiles as $f) {
            $present[$f['filename']] = true;
        }

        // Which setting(s) point at a given file, and the other way round.
        $usedBy = array();
        foreach (($category['expected'] ?? array()) as $settingName => $expectedFile) {
            if ($expectedFile !== null && $expectedFile !== '') {
                $usedBy[$expectedFile][] = $settingName;
            }
        }
        $totalSize = 0;
        foreach ($categoryFiles as $f) {
            $totalSize += (int)$f['filesize'];
        }
        ?>
        <div class="card shadow-sm mb-4 ss-section" style="--ss-accent: <?= h($meta['accent']) ?>;">

            <div class="card-header ss-section-header" style="cursor:default;">
                <span class="ss-section-icon"><i class="fas fa-<?= h($meta['icon']) ?>"></i></span>
                <div class="flex-grow-1">
                    <div class="fw-semibold"><?= h($category['name']) ?></div>
                    <div class="text-muted" style="font-size:.78rem;"><?= h($category['description']) ?></div>
                </div>
                <span class="badge rounded-pill bg-body-tertiary text-body-secondary"
                      title="<?= h(__('Files in this directory')) ?>">
                    <i class="fas fa-file me-1"></i><?= h(count($categoryFiles)) ?>
                </span>
                <?php if ($totalSize): ?>
                    <span class="badge rounded-pill bg-body-tertiary text-body-secondary"
                          title="<?= h(__('Total size')) ?>">
                        <i class="fas fa-hard-drive me-1"></i><?= h($formatBytes($totalSize)) ?>
                    </span>
                <?php endif; ?>
            </div>

            <div class="card-body">

                <div class="fl-meta mb-3">
                    <span><strong><?= __('Expected format') ?>:</strong> <?= h($category['valid_format']) ?></span>
                    <span class="mx-2">·</span>
                    <span><strong><?= __('Path') ?>:</strong> <code><?= h($category['path']) ?></code></span>
                </div>

                <!-- SETTINGS POINTING AT A FILE -->
                <?php if (!empty($category['expected'])): ?>
                    <div class="fl-expected mb-3">
                        <div class="fl-block-title"><?= __('Referenced by settings') ?></div>
                        <?php foreach ($category['expected'] as $settingName => $expectedFile): ?>
                            <?php
                            if ($expectedFile === null || $expectedFile === '') {
                                $state = array('level' => null, 'icon' => 'minus', 'label' => __('not set'));
                            } elseif (!empty($present[$expectedFile])) {
                                $state = array('level' => 2, 'icon' => 'circle-check', 'label' => __('present'));
                            } else {
                                $state = array('level' => 0, 'icon' => 'circle-xmark', 'label' => __('missing'));
                            }
                            ?>
                            <div class="d-flex flex-wrap align-items-center gap-2 fl-expected-row">
                                <span class="ss-setting-name"><?= h($settingName) ?></span>
                                <i class="fas fa-arrow-right text-muted" style="font-size:.65rem;"></i>
                                <span class="fl-figures">
                                    <?= $expectedFile === null || $expectedFile === ''
                                        ? '<span class="text-muted fst-italic">' . __('no file configured') . '</span>'
                                        : h($expectedFile) ?>
                                </span>
                                <?php if ($state['level'] === null): ?>
                                    <span class="badge text-bg-secondary ss-posture"><?= h($state['label']) ?></span>
                                <?php else: ?>
                                    <span class="ss-prio ss-lvl-<?= (int)$state['level'] ?>">
                                        <i class="fas fa-<?= h($state['icon']) ?>"></i><?= h($state['label']) ?>
                                    </span>
                                <?php endif; ?>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <!-- FILE GRID -->
                <?php if (empty($categoryFiles)): ?>
                    <div class="text-center text-muted py-4">
                        <i class="fas fa-folder-open fa-2x mb-2 d-block opacity-50"></i>
                        <?= __('No file uploaded in this directory yet.') ?>
                    </div>
                <?php else: ?>
                    <div class="row g-3">
                        <?php foreach ($categoryFiles as $f): ?>
                            <?php
                            $filename = $f['filename'];
                            $filesize = (int)$f['filesize'];

                            $flags = '';
                            if ($f['link']) $flags .= 'l';
                            if ($f['read']) $flags .= 'r';
                            if ($f['write']) $flags .= 'w';
                            if ($f['execute']) $flags .= 'x';

                            // Not readable → nothing renders it; not writable → it cannot be deleted.
                            $permissionWarning = null;
                            if (!$f['read']) {
                                $permissionWarning = __('Not readable — MISP cannot serve this file.');
                            } elseif (!$f['write']) {
                                $permissionWarning = __('Not writable — this file cannot be deleted from here.');
                            }

                            $preview = null;
                            if ($f['read'] && $filesize > 0 && $filesize <= $previewMaxFile && $filesize <= $previewBudget) {
                                $preview = $this->Image->base64($category['path'] . DS . $filename);
                                if ($preview === 'data:null') {
                                    $preview = null;
                                } else {
                                    $previewBudget -= $filesize;
                                }
                            } elseif ($f['read'] && $filesize > 0) {
                                $previewsSkipped++;
                            }

                            $deleteId = $uid . '-del-' . md5($type . '/' . $filename);
                            $confirmations[$deleteId] = array(
                                'title' => __('Delete %s', $filename),
                                'body' => '<p class="mb-0 text-muted small">'
                                    . h(__('The file is removed from %s. Any setting still pointing at it will stop resolving.', $category['path']))
                                    . '</p>',
                                'label' => __('Delete the file'),
                                'cls' => 'btn-danger',
                            );
                            ?>
                            <div class="col-6 col-md-4 col-xl-3">
                                <div class="fl-tile h-100">

                                    <div class="fl-thumb">
                                        <?php if ($preview !== null): ?>
                                            <img src="<?= $preview ?>" alt="<?= h($filename) ?>" loading="lazy">
                                        <?php else: ?>
                                            <i class="fas fa-file-image text-muted opacity-50"></i>
                                        <?php endif; ?>
                                    </div>

                                    <div class="fl-tile-body">
                                        <div class="fl-tile-name" title="<?= h($filename) ?>"><?= h($filename) ?></div>

                                        <div class="fl-figures text-muted">
                                            <?= h($formatBytes($filesize)) ?>
                                            <span class="mx-1">·</span>
                                            <span title="<?= h(__('link / read / write / execute')) ?>"><?= h($flags ?: '—') ?></span>
                                        </div>

                                        <?php if (!empty($usedBy[$filename])): ?>
                                            <div class="mt-1">
                                                <?php foreach ($usedBy[$filename] as $settingName): ?>
                                                    <span class="badge text-bg-primary ss-posture"><?= h($settingName) ?></span>
                                                <?php endforeach; ?>
                                            </div>
                                        <?php endif; ?>

                                        <?php if ($permissionWarning): ?>
                                            <div class="mt-1">
                                                <span class="ss-prio ss-lvl-0" title="<?= h($permissionWarning) ?>">
                                                    <i class="fas fa-triangle-exclamation"></i><?= __('permissions') ?>
                                                </span>
                                            </div>
                                        <?php endif; ?>
                                    </div>

                                    <button type="button" class="btn btn-sm btn-outline-danger fl-tile-delete"
                                            onclick="flConfirm('<?= h($deleteId) ?>')"
                                            title="<?= h(__('Delete this file')) ?>"
                                            aria-label="<?= h(__('Delete %s', $filename)) ?>">
                                        <i class="fas fa-trash"></i>
                                    </button>

                                    <?= $this->Form->postLink('',
                                        array('controller' => 'servers', 'action' => 'deleteFile', $type, $filename),
                                        array('id' => $deleteId, 'class' => 'd-none', 'escape' => false)) ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <!-- UPLOAD -->
            <div class="card-footer bg-transparent">
                <?= $this->Form->create('Server', array(
                    'type' => 'file',
                    'url' => $baseurl . '/servers/uploadFile/' . h($type),
                    'class' => 'd-flex flex-wrap align-items-center gap-2 mb-0',
                )) ?>
                    <?= $this->Form->file('file', array(
                        'class' => 'form-control form-control-sm',
                        'accept' => $svgAllowed ? 'image/png,image/svg+xml' : 'image/png',
                        'style' => 'max-width:22rem;',
                    )) ?>
                    <button type="submit" class="btn btn-sm btn-primary">
                        <i class="fas fa-upload me-1"></i><?= __('Upload') ?>
                    </button>
                    <span class="text-muted fl-figures">
                        <?php if ($svgAllowed): ?>
                            <?= __('PNG or SVG.') ?>
                        <?php else: ?>
                            <?= __('PNG only — SVG uploads are disabled by Security.enable_svg_logos.') ?>
                        <?php endif; ?>
                        <?= __('An existing file has to be deleted before it can be replaced.') ?>
                    </span>
                <?= $this->Form->end() ?>
            </div>
        </div>
    <?php endforeach; ?>

    <?php if ($previewsSkipped): ?>
        <div class="alert alert-secondary d-flex gap-2" role="alert">
            <i class="fas fa-circle-info mt-1"></i>
            <div><?= __('%s file(s) are shown without a preview: they are either larger than %s or beyond the preview budget of this page.',
                h($previewsSkipped), h($formatBytes($previewMaxFile))) ?></div>
        </div>
    <?php endif; ?>

</div>

<script>
(function () {
    var FL = <?= json_encode($confirmations, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var CANCEL = <?= json_encode(__('Cancel')) ?>;

    window.flConfirm = function (id) {
        var conf = FL[id];
        var trigger = document.getElementById(id);
        if (!conf || !trigger) return;
        showConfirmModal({
            title: conf.title,
            body: conf.body,
            confirmLabel: conf.label,
            confirmClass: conf.cls,
            cancelLabel: CANCEL,
            onConfirm: function () { trigger.click(); }
        });
    };
})();
</script>
