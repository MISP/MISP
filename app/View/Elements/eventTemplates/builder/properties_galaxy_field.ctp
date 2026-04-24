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
    <label><?php echo __('Restrict to galaxy types (comma-separated)'); ?></label>
    <input type="text" data-et-field-csv="restrict_galaxy_types" class="input-block-level"
           placeholder="threat-actor, mitre-attack-pattern">
    <span class="help-block">
        <?php echo __('Full galaxy-type picker lands in the next builder commit.'); ?>
    </span>
</div>
