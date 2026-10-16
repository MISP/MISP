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

// The theme's --misp-tone-<hue>-* token for each tile colour above.
$toneHues = [
    '#cfe2ff' => 'blue', '#f8d7da' => 'red', '#d1e7dd' => 'green',
    '#d0f4de' => 'green', '#d4e8c4' => 'green', '#fff3cd' => 'yellow',
    '#e2e3e5' => 'gray', '#fce4d6' => 'orange', '#ffe5d0' => 'orange',
    '#e9d7f5' => 'purple',
];
$tone = function (array $cfg, $role) use ($toneHues) {
    $value = $role === 'bg' ? $cfg['bg'] : $cfg['color'];
    if (!isset($toneHues[$cfg['bg']])) {
        return $value;
    }
    return sprintf('var(--misp-tone-%s-%s, %s)', $toneHues[$cfg['bg']], $role, $value);
};
?>

<div data-attachment-count="<?= count($attachments) ?>">

<?php if (empty($attachments)): ?>

    <p class="eo-empty" data-attachment-empty><?= __('No file attached to this event.') ?></p>

<?php else: ?>

    <ul class="eo-files" data-attachment-list>
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

        $ext      = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $extUpper = strtoupper($ext ?: '???');

        $searchText = strtolower(implode(' ', array_filter([
            $filename, $att['category'], $att['comment'],
            $hash, $cfg['mime'] ?? '', $extUpper
        ])));
    ?>
        <li class="eo-file" data-attachment-row data-search-text="<?= h($searchText) ?>">
            <span class="eo-file-icon"
                  style="background-color:<?= h($tone($cfg, 'bg')) ?>;color:<?= h($tone($cfg, 'fg')) ?>;">
                <i class="fas <?= h($cfg['icon']) ?>"></i>
            </span>

            <div class="eo-file-main">
                <div class="eo-file-name" title="<?= h($filename) ?>"><?= h($filename) ?></div>
                <div class="eo-file-meta">
                    <span class="eo-file-ext"
                          style="background-color:<?= h($tone($cfg, 'bg')) ?>;color:<?= h($tone($cfg, 'fg')) ?>;">
                        .<?= h($extUpper) ?>
                    </span>
                    <span><?= h($att['category']) ?></span>
                    <?php if (!empty($att['timestamp'])): ?>
                        <span><?= $this->Time->time($att['timestamp']) ?></span>
                    <?php endif; ?>
                    <?php if (!empty($hash)): ?>
                        <span class="font-monospace" title="<?= h($hash) ?>"><?= h(substr($hash, 0, 12)) ?>…</span>
                    <?php endif; ?>
                </div>
                <?php if (!empty($att['comment'])): ?>
                    <div class="eo-file-comment" title="<?= h($att['comment']) ?>">
                        <i class="fas fa-comment"></i><?= h($att['comment']) ?>
                    </div>
                <?php endif; ?>
            </div>

            <?= $this->element('genericElementsBS5/Badges/distribution', [
                'distribution' => (int)($att['distribution'] ?? 0),
                'full'         => false,
            ]); ?>

            <a href="<?= h($baseurl . '/attributes/download/' . $att['id']) ?>"
               class="btn btn-sm btn-outline-primary flex-shrink-0"
               title="<?= __('Download') ?>"
               aria-label="<?= __('Download') ?>">
                <i class="fas fa-download"></i>
            </a>
        </li>
    <?php endforeach; ?>
    </ul>

    <div class="d-none eo-empty border-top" data-attachment-noresult>
        <?= __('No attachment matches this filter.') ?>
    </div>

<?php endif; ?>

</div>
