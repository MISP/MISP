<?php
    $content = isset($element['content']) ? (string)$element['content'] : '';
?>
<div class="et-text-block alert alert-light border-start border-3 border-secondary mb-3">
    <?= $this->EventTemplateMarkdown->render($content) ?>
</div>
