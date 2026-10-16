<?php
/**
 * Variables attendues :
 * - $formatName (string)
 * - $hiddenClass (string)
 */
$formatName = h($formatName);
?>

<span class="badge misp-format-badge me-1 mb-1 <?= $hiddenClass ?>">
    <i class="fas fa-terminal me-1"></i>
    <?= $formatName ?>
</span>
