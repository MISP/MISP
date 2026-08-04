<h4><?php echo __('Event report properties'); ?></h4>
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
</div>
<div class="control-group">
    <label><?php echo __('Default content (Markdown)'); ?></label>
    <textarea data-et-field="default_content" rows="6" class="input-block-level"></textarea>
    <span class="help-block">
        <?php echo __('Pre-fills the report body the user starts editing from. The filled value is saved as an EventReport row attached to the new event.'); ?>
    </span>
</div>
