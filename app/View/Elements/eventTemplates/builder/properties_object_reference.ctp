<h4><?php echo __('Object reference properties'); ?></h4>
<div class="alert alert-info" style="margin-bottom:10px;">
    <?php echo __('Object references are not user-facing; they materialise a relationship between two object fields when the event is created.'); ?>
</div>
<div class="control-group">
    <label><?php echo __('Stable id'); ?></label>
    <input type="text" data-et-field="id" class="input-block-level" disabled>
</div>
<div class="control-group">
    <label><?php echo __('From (source object field)'); ?> <span class="red">*</span></label>
    <select data-et-field="from" data-et-object-field-select class="input-block-level">
        <option value=""><?php echo __('— select —'); ?></option>
    </select>
</div>
<div class="control-group">
    <label><?php echo __('To (target object field)'); ?> <span class="red">*</span></label>
    <select data-et-field="to" data-et-object-field-select class="input-block-level">
        <option value=""><?php echo __('— select —'); ?></option>
    </select>
</div>
<div class="control-group">
    <label><?php echo __('Relationship type'); ?> <span class="red">*</span></label>
    <input type="text" data-et-field="relationship_type" class="input-block-level"
           placeholder="has-attachment">
</div>
<div class="control-group">
    <label><?php echo __('Comment'); ?></label>
    <input type="text" data-et-field="comment" class="input-block-level">
</div>
