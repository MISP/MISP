<?php
    $content = isset($element['content']) ? (string)$element['content'] : '';
?>
<div class="et-text-block" style="margin:12px 0; padding:10px 12px; background:#f9f9f9; border-left:3px solid #ddd;">
    <?php echo $this->EventTemplateMarkdown->render($content); ?>
</div>
