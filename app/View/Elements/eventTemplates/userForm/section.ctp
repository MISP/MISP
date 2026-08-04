<?php
    $label = isset($element['label']) ? (string)$element['label'] : '';
    $help = isset($element['help']) ? (string)$element['help'] : '';
?>
<header class="et-section-header">
    <h3 class="et-section-title"><?php echo h($label); ?></h3>
    <?php if ($help !== ''): ?>
        <div class="et-section-help">
            <?php echo $this->EventTemplateMarkdown->render($help); ?>
        </div>
    <?php endif; ?>
</header>
