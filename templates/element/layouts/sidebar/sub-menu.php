<?php
    $seed = $seed ?? 'sd-' . mt_rand();
?>

<div id="<?= $seed ?>" class="collapse <?= !empty($open) ? 'show' : '' ?>">
    <ul class="sub-menu">
        <?php foreach ($children as $childName => $child): ?>
            <?= $this->element('layouts/sidebar/entry', [
                    'parentName' => $childName,
                    'parent' => $child,
                ])
            ?>
        <?php endforeach; ?>
    </ul>
</div>
