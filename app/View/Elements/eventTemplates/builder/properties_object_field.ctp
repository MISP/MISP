<?php
    $objectTemplates = isset($objectTemplatesAvailable)
        ? $objectTemplatesAvailable
        : array();
?>
<h4><?php echo __('Object field properties'); ?></h4>
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
        <?php echo __('Mandatory'); ?>
    </label>
    <label class="checkbox">
        <input type="checkbox" data-et-field="repeatable">
        <?php echo __('Repeatable (user can add multiple object instances)'); ?>
    </label>
</div>
<hr>
<div class="control-group">
    <label><?php echo __('Object template'); ?> <span class="red">*</span></label>
    <select data-et-object-template-select class="input-block-level">
        <option value=""><?php echo __('— select an object template —'); ?></option>
        <?php foreach ($objectTemplates as $ot): ?>
            <?php
                $optVal = $ot['uuid'] . '@' . $ot['version'];
                $optLabel = sprintf(
                    '%s — v%d (%s)',
                    $ot['name'],
                    $ot['version'],
                    $ot['meta_category']
                );
            ?>
            <option value="<?php echo h($optVal); ?>"
                    data-name="<?php echo h($ot['name']); ?>"
                    data-version="<?php echo h($ot['version']); ?>">
                <?php echo h($optLabel); ?>
            </option>
        <?php endforeach; ?>
    </select>
    <span class="help-block"><?php echo __('Picks the object_template.uuid + pinned_version. Only active templates are listed.'); ?></span>
</div>
<div class="control-group">
    <label><?php echo __('Current uuid'); ?></label>
    <input type="text" data-et-field="object_template.uuid" class="input-block-level" readonly>
</div>
<div class="control-group">
    <label><?php echo __('Current name'); ?></label>
    <input type="text" data-et-field="object_template.name" class="input-block-level" readonly>
</div>
<div class="control-group">
    <label><?php echo __('Pinned version'); ?></label>
    <input type="text" data-et-field="object_template.pinned_version" class="input-block-level" readonly>
</div>
<div class="alert alert-info" style="margin-top:10px;">
    <?php echo __('Per-relation overrides (mandatory, hidden, label/help override) land in the next builder commit. For now the object field renders all relations to the user with object-template defaults.'); ?>
</div>
