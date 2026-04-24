<?php
    $label = isset($element['label']) ? (string)$element['label'] : '';
    $help = isset($element['help']) ? (string)$element['help'] : '';
?>
<div class="et-section" style="margin-top:24px;">
    <h3 style="margin-bottom:4px;"><?php echo h($label); ?></h3>
    <?php if ($help !== ''): ?>
        <div class="et-help" style="color:#666; margin-bottom:8px;">
            <?php echo $this->EventTemplateMarkdown->render($help); ?>
        </div>
    <?php endif; ?>
    <hr style="margin-top:4px; margin-bottom:12px;">
</div>
