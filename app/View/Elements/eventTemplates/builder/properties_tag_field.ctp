<h4><?php echo __('Tag field properties'); ?></h4>
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
        <input type="checkbox" data-et-field="multiple">
        <?php echo __('Allow multiple tags'); ?>
    </label>
</div>
<div class="control-group">
    <label><?php echo __('Restrict to taxonomies'); ?></label>
    <div style="display:flex; gap:8px; align-items:center;">
        <button type="button" class="btn"
                data-et-open-multipicker="taxonomies"
                data-et-multipicker-field="restrict_taxonomies"
                data-et-multipicker-title="<?php echo __('Select taxonomies'); ?>">
            <i class="fa fa-tags"></i> <?php echo __('Choose…'); ?>
        </button>
        <span class="et-multipicker-summary" data-et-multipicker-summary-for="restrict_taxonomies">
            <em><?php echo __('(any taxonomy)'); ?></em>
        </span>
    </div>
    <span class="help-block">
        <?php echo __('Empty list = the user can pick any tag. Otherwise restricted to tags from the chosen taxonomies.'); ?>
    </span>
</div>
