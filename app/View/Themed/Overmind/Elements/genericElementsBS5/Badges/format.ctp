<?php
/**
 * Variables attendues :
 * - $formatName (string)
 * - $hiddenClass (string)
 */
$formatName = h($formatName);

$style = "
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
    font-size: 0.75rem;
    background-color: #242424;
    color: #f0f0f0;
    border-left: 3px solid #1892B1;
    padding: 0.35em 0.65em;
    letter-spacing: 0.02em;
    box-shadow: 2px 2px 5px rgba(0,0,0,0.1);
";
?>

<span class="badge me-1 mb-1 <?= $hiddenClass ?>" style="<?= $style ?>">
    <i class="fas fa-terminal me-1" style="font-size: 0.65rem; color: #1892B1;"></i>
    <?= $formatName ?>
</span>