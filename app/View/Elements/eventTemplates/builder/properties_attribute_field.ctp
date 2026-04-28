<?php
    $categories = isset($attributeCategoryDefinitions)
        ? $attributeCategoryDefinitions
        : array();
?>
<h4><?php echo __('Attribute field properties'); ?></h4>
<div class="control-group">
    <label><?php echo __('Stable id'); ?></label>
    <input type="text" data-et-field="id" class="input-block-level" disabled>
</div>
<div class="control-group">
    <label><?php echo __('Label'); ?> <span class="red">*</span></label>
    <input type="text" data-et-field="label" class="input-block-level">
</div>
<div class="control-group">
    <label><?php echo __('Help text (Markdown)'); ?></label>
    <textarea data-et-field="help" rows="2" class="input-block-level"></textarea>
</div>
<div class="control-group">
    <label class="checkbox">
        <input type="checkbox" data-et-field="mandatory">
        <?php echo __('Mandatory (user must fill this field)'); ?>
    </label>
    <label class="checkbox">
        <input type="checkbox" data-et-field="repeatable">
        <?php echo __('Repeatable (user can add multiple values)'); ?>
    </label>
</div>
<hr>
<div class="control-group">
    <label><?php echo __('MISP category'); ?> <span class="red">*</span></label>
    <select data-et-field="misp.category" class="input-block-level">
        <option value=""><?php echo __('— select —'); ?></option>
        <?php foreach (array_keys($categories) as $cat): ?>
            <option value="<?php echo h($cat); ?>"><?php echo h($cat); ?></option>
        <?php endforeach; ?>
    </select>
</div>
<div class="control-group">
    <label><?php echo __('MISP type'); ?> <span class="red">*</span></label>
    <select data-et-field="misp.type" class="input-block-level">
        <option value=""><?php echo __('— select a category first —'); ?></option>
    </select>
    <span class="help-block"><?php echo __('Types are filtered to the selected category.'); ?></span>
</div>
<div class="control-group">
    <label class="checkbox">
        <input type="checkbox" data-et-field="misp.to_ids_default">
        <?php echo __('Default to_ids = true'); ?>
    </label>
</div>
<div class="control-group">
    <label><?php echo __('Comment template'); ?></label>
    <input type="text" data-et-field="misp.comment_template" class="input-block-level">
    <span class="help-block"><?php echo __('Pre-filled on the attribute’s comment field when the user submits.'); ?></span>
</div>
<div class="control-group">
    <label><?php echo __('Default value'); ?></label>
    <input type="text" data-et-field="misp.default_value" class="input-block-level">
</div>
