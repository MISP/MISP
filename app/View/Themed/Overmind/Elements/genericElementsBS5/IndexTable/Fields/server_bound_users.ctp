<?php
$boundUsers = Hash::get($row, $field['data_path']);
$isCard = isset($viewMode) && $viewMode === 'card';
if (empty($boundUsers)) {
    if ($isCard) {
        echo '<span class="small text-muted">' .
            __('No bound sync user configured.') . '</span>';
    } else {
        echo '<span class="text-muted">' . __('None') . '</span>';
    }
    return;
}

if (!is_array($boundUsers)) {
    $boundUsers = [$boundUsers];
}
?>
<div class="d-flex flex-column gap-1">
    <?php foreach ($boundUsers as $boundUser): ?>
        <?php
        if (is_array($boundUser)) {
            $displayValue = $boundUser['email'] ?? reset($boundUser);
        } else {
            $displayValue = $boundUser;
        }
        ?>
        <?php if ($isCard): ?>
            <span class="small text-muted">
                <?= __('Bound sync user: %s', h($displayValue)) ?>
            </span>
        <?php else: ?>
            <span class="small"><?= h($displayValue) ?></span>
        <?php endif; ?>
    <?php endforeach; ?>
</div>
