<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $defaultContent = isset($element['default_content']) ? (string)$element['default_content'] : '';
?>
<div class="et-field et-event-report-field" data-et-element-id="<?php echo h($id); ?>"
     data-et-element-type="event_report" data-et-mandatory="<?php echo $mandatory ? '1' : '0'; ?>"
     style="margin:10px 0;">
    <label for="et-input-<?php echo h($id); ?>" style="font-weight:600;">
        <?php echo h($label); ?>
        <?php if ($mandatory): ?><span class="red" title="<?php echo __('Mandatory'); ?>">*</span><?php endif; ?>
        <span style="color:#888; font-size:11px; font-weight:normal;">
            (<?php echo __('event report'); ?>)
        </span>
    </label>
    <?php if ($help !== ''): ?>
        <div class="et-help" style="color:#666; font-size:12px; margin:2px 0 4px 0;">
            <?php echo $this->EventTemplateMarkdown->render($help); ?>
        </div>
    <?php endif; ?>
    <textarea id="et-input-<?php echo h($id); ?>"
              class="input-block-level et-value"
              data-et-path="<?php echo h($id); ?>"
              rows="12"><?php echo h($defaultContent); ?></textarea>
</div>
