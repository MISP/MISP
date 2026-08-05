<?php

$extMap = [
    /* images */
    'jpg'  => ['icon'=>'fa-file-image',       'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'image/jpeg'],
    'jpeg' => ['icon'=>'fa-file-image',       'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'image/jpeg'],
    'png'  => ['icon'=>'fa-file-image',       'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'image/png'],
    'gif'  => ['icon'=>'fa-file-image',       'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'image/gif'],
    'bmp'  => ['icon'=>'fa-file-image',       'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'image/bmp'],
    'svg'  => ['icon'=>'fa-file-image',       'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'image/svg+xml'],
    'webp' => ['icon'=>'fa-file-image',       'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'image/webp'],
    /* documents */
    'pdf'  => ['icon'=>'fa-file-pdf',         'bg'=>'#f8d7da', 'color'=>'#842029', 'mime'=>'application/pdf'],
    'doc'  => ['icon'=>'fa-file-word',        'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'application/msword'],
    'docx' => ['icon'=>'fa-file-word',        'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    'xls'  => ['icon'=>'fa-file-excel',       'bg'=>'#d1e7dd', 'color'=>'#0f5132', 'mime'=>'application/vnd.ms-excel'],
    'xlsx' => ['icon'=>'fa-file-excel',       'bg'=>'#d1e7dd', 'color'=>'#0f5132', 'mime'=>'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    'ppt'  => ['icon'=>'fa-file-powerpoint',  'bg'=>'#fff3cd', 'color'=>'#856404', 'mime'=>'application/vnd.ms-powerpoint'],
    'pptx' => ['icon'=>'fa-file-powerpoint',  'bg'=>'#fff3cd', 'color'=>'#856404', 'mime'=>'application/vnd.openxmlformats-officedocument.presentationml.presentation'],
    'txt'  => ['icon'=>'fa-file-alt',         'bg'=>'#e2e3e5', 'color'=>'#41464b', 'mime'=>'text/plain'],
    'csv'  => ['icon'=>'fa-file-csv',         'bg'=>'#d1e7dd', 'color'=>'#0f5132', 'mime'=>'text/csv'],
    'xml'  => ['icon'=>'fa-file-code',        'bg'=>'#e2e3e5', 'color'=>'#41464b', 'mime'=>'application/xml'],
    /* data / code */
    'json' => ['icon'=>'fa-file-code',        'bg'=>'#d0f4de', 'color'=>'#0a6640', 'mime'=>'application/json'],
    'py'   => ['icon'=>'fa-file-code',        'bg'=>'#fce4d6', 'color'=>'#7d2d00', 'mime'=>'text/x-python'],
    'js'   => ['icon'=>'fa-file-code',        'bg'=>'#fff3cd', 'color'=>'#856404', 'mime'=>'text/javascript'],
    'sh'   => ['icon'=>'fa-file-code',        'bg'=>'#e2e3e5', 'color'=>'#41464b', 'mime'=>'text/x-shellscript'],
    'ps1'  => ['icon'=>'fa-file-code',        'bg'=>'#cfe2ff', 'color'=>'#0a58ca', 'mime'=>'text/x-powershell'],
    'bat'  => ['icon'=>'fa-file-code',        'bg'=>'#e2e3e5', 'color'=>'#41464b', 'mime'=>'text/x-bat'],
    'vbs'  => ['icon'=>'fa-file-code',        'bg'=>'#e2e3e5', 'color'=>'#41464b', 'mime'=>'text/vbscript'],
    /* yara */
    'yar'  => ['icon'=>'fa-shield-alt',       'bg'=>'#d4e8c4', 'color'=>'#3d6b1a', 'mime'=>'text/x-yara'],
    'yara' => ['icon'=>'fa-shield-alt',       'bg'=>'#d4e8c4', 'color'=>'#3d6b1a', 'mime'=>'text/x-yara'],
    /* archives */
    'zip'  => ['icon'=>'fa-file-archive',     'bg'=>'#e9d7f5', 'color'=>'#5a0099', 'mime'=>'application/zip'],
    'gz'   => ['icon'=>'fa-file-archive',     'bg'=>'#e9d7f5', 'color'=>'#5a0099', 'mime'=>'application/gzip'],
    'tar'  => ['icon'=>'fa-file-archive',     'bg'=>'#e9d7f5', 'color'=>'#5a0099', 'mime'=>'application/x-tar'],
    '7z'   => ['icon'=>'fa-file-archive',     'bg'=>'#e9d7f5', 'color'=>'#5a0099', 'mime'=>'application/x-7z-compressed'],
    'rar'  => ['icon'=>'fa-file-archive',     'bg'=>'#e9d7f5', 'color'=>'#5a0099', 'mime'=>'application/x-rar-compressed'],
    /* executables */
    'exe'  => ['icon'=>'fa-skull',            'bg'=>'#ffe5d0', 'color'=>'#8b3a00', 'mime'=>'application/x-msdownload'],
    'dll'  => ['icon'=>'fa-skull',            'bg'=>'#ffe5d0', 'color'=>'#8b3a00', 'mime'=>'application/x-msdownload'],
    'bin'  => ['icon'=>'fa-skull',            'bg'=>'#ffe5d0', 'color'=>'#8b3a00', 'mime'=>'application/octet-stream'],
    'elf'  => ['icon'=>'fa-skull',            'bg'=>'#ffe5d0', 'color'=>'#8b3a00', 'mime'=>'application/x-elf'],
    'msi'  => ['icon'=>'fa-skull',            'bg'=>'#ffe5d0', 'color'=>'#8b3a00', 'mime'=>'application/x-msi'],
    'so'   => ['icon'=>'fa-skull',            'bg'=>'#ffe5d0', 'color'=>'#8b3a00', 'mime'=>'application/x-sharedlib'],
];

$malwareCfg = ['icon'=>'fa-virus', 'bg'=>'#f8d7da', 'color'=>'#842029', 'mime'=>'application/zip'];
$defaultCfg = ['icon'=>'fa-file',  'bg'=>'#e2e3e5', 'color'=>'#41464b', 'mime'=>'application/octet-stream'];
?>

<div data-attachment-count="<?= count($attachments) ?>">

<?php if (empty($attachments)): ?>

    <div class="d-flex flex-column align-items-center justify-content-center
                text-muted py-5" data-attachment-empty>
        <i class="fas fa-paperclip fa-2x mb-2 opacity-50"></i>
        <p class="mb-0 small fw-semibold">
            <?= __('No attachments found for this event.') ?>
        </p>
    </div>

<?php else: ?>

    <div class="table-responsive">
        <table class="table table-hover align-middle mb-0">

            <thead class="table-light border-bottom">
                <tr class="small text-uppercase text-muted fw-semibold">
                    <th class="ps-3" style="min-width:240px;">
                        <?= __('Filename / Type') ?>
                    </th>
                    <th><?= __('Mime Type') ?></th>
                    <th><?= __('Hash (Partial)') ?></th>
                    <th><?= __('Distribution') ?></th>
                    <th class="text-end pe-3"><?= __('Actions') ?></th>
                </tr>
            </thead>

            <tbody data-attachment-list>
            <?php foreach ($attachments as $att):
                $isMalware = ($att['type'] === 'malware-sample');

                if ($isMalware) {
                    $parts    = explode('|', $att['value'], 2);
                    $filename = $parts[0];
                    $hash     = $parts[1] ?? '';
                    $cfg      = $malwareCfg;
                } else {
                    $filename = $att['value'];
                    $hash     = '';
                    $ext      = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                    $cfg      = $extMap[$ext] ?? $defaultCfg;
                }

                $ext     = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
                $extUpper = strtoupper($ext ?: '???');
                $mime    = $cfg['mime'] ?? 'application/octet-stream';

                $searchText = strtolower(implode(' ', array_filter([
                    $filename, $att['category'], $att['comment'],
                    $hash, $mime, $extUpper
                ])));
            ?>
                <tr data-attachment-row
                    data-search-text="<?= h($searchText) ?>">

                    <!-- FILENAME / TYPE -->
                    <td class="ps-3">
                        <div class="d-flex align-items-center gap-3">

                            <!-- Colored icon box -->
                            <div class="rounded-2 d-flex align-items-center
                                        justify-content-center flex-shrink-0"
                                 style="width:40px;height:40px;
                                        background-color:<?= h($cfg['bg']) ?>;">
                                <i class="fas <?= h($cfg['icon']) ?>"
                                   style="color:<?= h($cfg['color']) ?>;
                                          font-size:1.15rem;">
                                </i>
                            </div>

                            <div class="d-flex flex-column gap-1">
                                <div class="fw-semibold text-truncate"
                                     title="<?= h($filename) ?>">
                                    <?= h($filename) ?>
                                </div>
                                <div class="d-flex align-items-center gap-2 flex-wrap">
                                    <!-- Extension badge -->
                                    <span class="badge rounded-pill fw-semibold px-2"
                                          style="background-color:<?= h($cfg['bg']) ?>;
                                                 color:<?= h($cfg['color']) ?>;
                                                 font-size:.65rem;letter-spacing:.04em;">
                                        .<?= h($extUpper) ?>
                                    </span>
                                    <!-- Category / description -->
                                    <span class="d-flex small text-muted gap-2">
                                        <?= h($att['category']) ?>
                                         <?php if (!empty($att['timestamp'])): ?>
                                            <span>
                                                ·
                                                <i class="fas fa-clock"></i>
                                                <?= $this->Time->time($att['timestamp']) ?>
                                            </span>
                                        <?php endif; ?>
                                    </span>
                                </div>
                                <?php if (!empty($att['comment'])): ?>
                                    <div class="small text-muted text-truncate"
                                        title="<?= h($att['comment'] ?? '') ?>">
                                        <i class="fas fa-comment"></i>
                                        <?= h($att['comment'] ?? '') ?>
                                    </div>
                                <?php endif; ?>
                            </div>

                        </div>
                    </td>

                    <!-- SIZE (not given by the backend) -->

                    <!-- MIME TYPE -->
                    <td class="small text-muted">
                        <?= h($mime) ?>
                    </td>

                    <!-- HASH (partial) -->
                    <td class="font-monospace small text-muted">
                        <?php if (!empty($hash)): ?>
                            <span title="<?= h($hash) ?>">
                                <?= h(substr($hash, 0, 16)) ?>…
                            </span>
                        <?php else: ?>
                            <span class="opacity-25">—</span>
                        <?php endif; ?>
                    </td>

                    <!-- DISTRIBUTION -->
                    <td>
                        <?= $this->element('genericElementsBS5/Badges/distribution', [
                            'distribution' => (int)($att['distribution'] ?? 0),
                            'full'         => true,
                        ]); ?>
                    </td>

                    <!-- ACTIONS -->
                    <td class="text-end pe-3">
                        <a href="<?= h($baseurl . '/attributes/download/' . $att['id']) ?>"
                           class="btn btn-sm btn-outline-primary"
                           title="<?= __('Download') ?>"
                           aria-label="<?= __('Download') ?>">
                            <i class="fas fa-download"></i>
                        </a>
                    </td>

                </tr>
            <?php endforeach; ?>
            </tbody>

        </table>
    </div>

    <!-- No-results row shown by JS when search yields nothing -->
    <div class="d-none text-center text-muted py-4 small border-top"
         data-attachment-noresult>
        <i class="fas fa-search me-2 opacity-50"></i>
        <?= __('No attachments match your search.') ?>
    </div>

<?php endif; ?>

</div>
