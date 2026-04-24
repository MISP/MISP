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
    <div style="display:flex; gap:8px; align-items:center;">
        <button type="button" class="btn" data-et-open-ot-picker>
            <i class="fa fa-search"></i> <?php echo __('Choose…'); ?>
        </button>
        <span class="et-ot-picker-current" style="font-weight:500; color:#333;">
            <span data-et-ot-display="name"><em><?php echo __('(none selected)'); ?></em></span>
            <span data-et-ot-display="version" class="muted" style="margin-left:4px;"></span>
            <span data-et-ot-display="meta" class="muted" style="margin-left:4px;"></span>
        </span>
    </div>
    <span class="help-block">
        <?php echo __('Opens a searchable list of active object templates on this instance.'); ?>
    </span>
</div>
<div class="control-group">
    <label><?php echo __('Current uuid'); ?></label>
    <input type="text" data-et-field="object_template.uuid" class="input-block-level" readonly>
</div>
<div class="control-group">
    <label><?php echo __('Pinned version'); ?></label>
    <input type="text" data-et-field="object_template.pinned_version" class="input-block-level" readonly>
</div>
<div class="alert alert-info" style="margin-top:10px;">
    <?php echo __('Per-relation overrides (mandatory, hidden, label/help override) land in a follow-up builder commit. For now the object field renders all relations to the user with object-template defaults.'); ?>
</div>
