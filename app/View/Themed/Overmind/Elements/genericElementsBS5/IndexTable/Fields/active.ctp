<?php

$value = Hash::get($row, $field['data_path']);
$isActive = !empty($value);
$isCard = isset($viewMode) && $viewMode === 'card';

$inactiveColor = '#f59e0b';
$inactiveBg    = 'rgba(245,158,11,0.08)';
$activeColor   = '#10b981';
$activeBg      = 'rgba(16,185,129,0.08)';

$title = $isActive
    ? ($field['title_on'] ?? '')
    : ($field['title_off'] ?? '');
?>

<?php if ($isCard || !$isActive): ?>

    <div class="d-flex align-items-center">
        <span class="badge px-2 py-1 text-uppercase"
              style="font-size:0.65em; letter-spacing:0.06em; font-weight:600;
                     border:1px solid <?= $isActive ? $activeColor : $inactiveColor ?>;
                     color:<?= $isActive ? $activeColor : $inactiveColor ?>;
                     background-color:<?= $isActive ? $activeBg : $inactiveBg ?>;"
              <?= $title === '' ? '' : 'title="' . h($title) . '"' ?>>
            <?= $isActive ? __('Active') : __('Inactive') ?>
        </span>
    </div>

<?php endif; ?>
