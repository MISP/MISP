<?php
    $label = isset($element['label']) ? (string)$element['label'] : '';
    $help = isset($element['help']) ? (string)$element['help'] : '';
?>
<header class="et-section-header card-header bg-white">
    <h3 class="et-section-title h6 fw-semibold mb-0"><?= h($label) ?></h3>
    <?php if ($help !== ''): ?>
        <div class="et-section-help text-muted small mt-1">
            <?= $this->EventTemplateMarkdown->render($help) ?>
        </div>
    <?php endif; ?>
</header>
