<?php
$value = Hash::get($row, $field['data_path']);
$isPublished = !empty($value);
$isCard = isset($viewMode) && $viewMode === 'card';


$unpublishedColor = '#f59e0b';
$unpublishedBg    = 'rgba(245,158,11,0.08)';
$publishedColor   = '#10b981';
$publishedBg      = 'rgba(16,185,129,0.08)';
?>

<?php if ($isCard): ?>

    <div class="d-flex align-items-center">
        <span class="badge px-2 py-1 text-uppercase"
              style="font-size:0.65em; letter-spacing:0.06em; font-weight:600;
                     border:1px solid <?= $isPublished ? $publishedColor : $unpublishedColor ?>;
                     color:<?= $isPublished ? $publishedColor : $unpublishedColor ?>;
                     background-color:<?= $isPublished ? $publishedBg : $unpublishedBg ?>;">
            <?= $isPublished ? __('Published') : __('Unpublished') ?>
        </span>
    </div>

<?php elseif (!$isPublished): ?>

    <div class="d-flex align-items-center">
        <span class="badge px-2 py-1 text-uppercase"
              style="font-size:0.65em; letter-spacing:0.06em; font-weight:600;
                     border:1px solid <?= $unpublishedColor ?>;
                     color:<?= $unpublishedColor ?>;
                     background-color:<?= $unpublishedBg ?>;">
            <?= __('Unpublished') ?>
        </span>
    </div>

<?php endif; ?>
