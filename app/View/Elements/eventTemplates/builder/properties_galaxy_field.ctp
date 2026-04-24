<h4><?php echo __('Galaxy field properties'); ?></h4>
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
        <?php echo __('Allow multiple clusters'); ?>
    </label>
</div>
<div class="control-group">
    <label><?php echo __('Restrict to galaxy types'); ?></label>
    <div style="display:flex; gap:8px; align-items:center;">
        <button type="button" class="btn"
                data-et-open-multipicker="galaxyTypes"
                data-et-multipicker-field="restrict_galaxy_types"
                data-et-multipicker-title="<?php echo __('Select galaxy types'); ?>">
            <i class="fa fa-globe"></i> <?php echo __('Choose…'); ?>
        </button>
        <span class="et-multipicker-summary" data-et-multipicker-summary-for="restrict_galaxy_types">
            <em><?php echo __('(any galaxy type)'); ?></em>
        </span>
    </div>
    <span class="help-block">
        <?php echo __('Empty list = the user can pick any galaxy cluster. Otherwise restricted to clusters from the chosen galaxy types.'); ?>
    </span>
</div>
