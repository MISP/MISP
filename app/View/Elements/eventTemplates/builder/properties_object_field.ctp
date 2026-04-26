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
    <label><?php echo __('Minimum version'); ?></label>
    <input type="text" data-et-field="object_template.minimum_version" class="input-block-level" readonly>
</div>
<hr>
<div class="control-group">
    <label><?php echo __('Relations to include in the user form'); ?></label>
    <div class="et-relations-panel">
        <div class="et-relations-empty" style="color:#888; font-style:italic; padding:8px 0;">
            <?php echo __('Pick an object template above to choose which relations the user will see.'); ?>
        </div>
        <div class="et-relations-controls" style="display:none; margin-bottom:4px; font-size:11px;">
            <a href="#" data-et-relations-all><?php echo __('Select all'); ?></a>
            <span style="color:#ccc;"> · </span>
            <a href="#" data-et-relations-none><?php echo __('Select none'); ?></a>
            <span style="color:#888; margin-left:8px;">
                <?php echo __('Empty selection = show all relations (object-template default).'); ?>
            </span>
        </div>
        <div class="et-relations-list"
             style="display:none; max-height:260px; overflow-y:auto;
                    border:1px solid #e6e6e6; border-radius:3px;">
        </div>
    </div>
</div>
