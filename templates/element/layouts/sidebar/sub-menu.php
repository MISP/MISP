<?php
    $seed = $seed ?? 'sd-' . mt_rand();
?>

<ul id="<?= $seed ?>" class="sub-menu collapse <?= !empty($open) ? 'show' : '' ?>">
    <?php foreach ($children as $childName => $child): ?>
        <?= $this->element('layouts/sidebar/entry', [
                'parentName' => $childName,
                'parent' => $child,
            ])
        ?>
    <?php endforeach; ?>
</ul>
