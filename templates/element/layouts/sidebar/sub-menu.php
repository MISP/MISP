<?php
    $seed = $seed ?? 'sd-' . mt_rand();
?>

<div id="<?= $seed ?>" class="collapse <?= !empty($open) ? 'show' : '' ?> submenu-container">
    <ul class="sub-menu dropdown-menu show" style="--bs-dropdown-border-radius: 0; --bs-dropdown-border-width: 0; position: relative;">
        <li><h6 class="dropdown-header"><?= h($submenuName ?? __('Sub Menu')) ?></h6></li>
        <?php foreach ($children as $childName => $child): ?>
            <?= $this->element('layouts/sidebar/entry', [
                    'parentName' => $childName,
                    'parent' => $child,
                ])
            ?>
        <?php endforeach; ?>
    </ul>
</div>
