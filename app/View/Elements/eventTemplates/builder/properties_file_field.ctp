<h4><?php echo __('File field properties'); ?></h4>
<div class="alert alert-warning" style="margin-bottom:10px;">
    <?php echo __('User input for file_field elements is rejected by the server in v1 (PRD §5.2 F2.11). Templates that declare file fields still save, but the user form will disable uploads until the upload pipeline lands.'); ?>
</div>
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
        <?php echo __('Repeatable (user can upload multiple files)'); ?>
    </label>
</div>
<div class="control-group">
    <label><?php echo __('Store uploaded files as'); ?></label>
    <select data-et-field="as" class="input-block-level">
        <option value="attachment"><?php echo __('attachment — general-purpose file attribute'); ?></option>
        <option value="malware-sample"><?php echo __('malware-sample — encrypted / quarantined sample'); ?></option>
    </select>
</div>
