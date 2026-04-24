<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $repeatable = !empty($element['repeatable']);
    $misp = isset($element['misp']) && is_array($element['misp']) ? $element['misp'] : array();
    $defaultValue = isset($misp['default_value']) ? (string)$misp['default_value'] : '';
    $typeHint = isset($misp['type']) ? (string)$misp['type'] : '';
    $categoryHint = isset($misp['category']) ? (string)$misp['category'] : '';
?>
<div class="et-field et-attribute-field" data-et-element-id="<?php echo h($id); ?>"
     data-et-element-type="attribute_field" data-et-mandatory="<?php echo $mandatory ? '1' : '0'; ?>"
     data-et-repeatable="<?php echo $repeatable ? '1' : '0'; ?>" style="margin:10px 0;">
    <label for="et-input-<?php echo h($id); ?>" style="font-weight:600;">
        <?php echo h($label); ?>
        <?php if ($mandatory): ?><span class="red" title="<?php echo __('Mandatory'); ?>">*</span><?php endif; ?>
        <span style="color:#888; font-size:11px; font-weight:normal;">
            (<?php echo h($categoryHint . ' / ' . $typeHint); ?>)
        </span>
    </label>
    <?php if ($help !== ''): ?>
        <div class="et-help" style="color:#666; font-size:12px; margin:2px 0 4px 0;">
            <?php echo $this->EventTemplateMarkdown->render($help); ?>
        </div>
    <?php endif; ?>
    <div class="et-entries">
        <div class="et-entry" style="display:flex; gap:6px; align-items:center; margin-bottom:4px;">
            <input type="text" id="et-input-<?php echo h($id); ?>"
                   class="input-block-level et-value"
                   data-et-path="<?php echo h($id); ?>"
                   value="<?php echo h($defaultValue); ?>">
            <?php if ($repeatable): ?>
                <button type="button" class="btn btn-mini et-remove-entry"
                        style="display:none;" title="<?php echo __('Remove'); ?>">×</button>
            <?php endif; ?>
        </div>
    </div>
    <?php if ($repeatable): ?>
        <button type="button" class="btn btn-mini et-add-entry">
            + <?php echo __('Add another'); ?>
        </button>
    <?php endif; ?>
</div>
