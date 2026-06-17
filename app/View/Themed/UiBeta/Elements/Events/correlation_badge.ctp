<?php
$count = isset($count) ? (int)$count : 0;
$title = isset($title) ? $title : __('Show correlations');
$tag = isset($tag) ? strtolower((string)$tag) : 'span';
$className = 'beta-related-count-badge';
if (!empty($class)) {
    $className .= ' ' . trim((string)$class);
}
?>
<style>
    .beta-related-count-badge {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 4px;
        min-width: 22px;
        height: 22px;
        padding: 0 7px;
        border: 1px solid #b7d5f0;
        border-radius: 999px;
        background: #eaf5ff;
        color: #3f78a8;
        font-size: 11px;
        font-weight: 600;
        line-height: 1;
        cursor: pointer;
        text-decoration: none;
        box-sizing: border-box;
        vertical-align: middle;
    }

    .beta-related-count-badge:hover,
    .beta-related-count-badge:focus {
        background: #e1f0ff;
        color: #356c99;
        border-color: #a7cbed;
        text-decoration: none;
    }

    .beta-related-count-badge .fa {
        font-size: 10px;
    }
</style>
<?php if ($tag === 'a'): ?>
    <a href="<?= h($href ?? '#') ?>" class="<?= h($className) ?>" title="<?= h($title) ?>">
        <i class="fa fa-code-branch" aria-hidden="true"></i><span><?= $count ?></span>
    </a>
<?php else: ?>
    <span class="<?= h($className) ?>" title="<?= h($title) ?>"<?php if (!empty($onclick)): ?> onclick="<?= h($onclick) ?>"<?php endif; ?>>
        <i class="fa fa-code-branch" aria-hidden="true"></i><span><?= $count ?></span>
    </span>
<?php endif; ?>
