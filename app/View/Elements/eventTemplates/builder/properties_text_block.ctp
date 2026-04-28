<h4><?php echo __('Text block properties'); ?></h4>
<div class="control-group">
    <label><?php echo __('Stable id'); ?></label>
    <input type="text" data-et-field="id" class="input-block-level" disabled>
</div>
<div class="control-group">
    <label><?php echo __('Content (Markdown)'); ?></label>
    <textarea data-et-field="content" rows="6" class="input-block-level"></textarea>
    <span class="help-block"><?php echo __('Rendered inline in the user form. Supports Markdown; raw HTML is stripped.'); ?></span>
</div>
