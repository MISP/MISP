<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $multiple = !empty($element['multiple']);
    $taxs = isset($element['restrict_taxonomies']) && is_array($element['restrict_taxonomies'])
        ? $element['restrict_taxonomies']
        : array();
?>
<div class="et-field et-tag-field" data-et-element-id="<?php echo h($id); ?>"
     data-et-element-type="tag_field" data-et-mandatory="<?php echo $mandatory ? '1' : '0'; ?>"
     data-et-multiple="<?php echo $multiple ? '1' : '0'; ?>"
     data-et-restrict-taxonomies="<?php echo h(JsonTool::encode($taxs)); ?>"
     style="margin:10px 0;">
    <label style="font-weight:600;">
        <?php echo h($label); ?>
        <?php if ($mandatory): ?><span class="red">*</span><?php endif; ?>
    </label>
    <?php if ($help !== ''): ?>
        <div class="et-help" style="color:#666; font-size:12px; margin:2px 0 4px 0;">
            <?php echo $this->EventTemplateMarkdown->render($help); ?>
        </div>
    <?php endif; ?>
    <div style="display:flex; gap:6px; align-items:center;">
        <input type="text" class="input-block-level et-value"
               data-et-path="<?php echo h($id); ?>"
               data-et-csv="1"
               style="flex:1; margin-bottom:0;"
               placeholder="<?php
                   echo $multiple
                       ? __('Comma-separated tag names (e.g. tlp:amber, kill-chain:reconnaissance)')
                       : __('A single tag name (e.g. tlp:amber)');
               ?>">
        <button type="button" class="btn" data-et-open-tag-picker="<?php echo h($id); ?>">
            <i class="fa fa-tags"></i> <?php echo __('Choose…'); ?>
        </button>
    </div>
    <?php if (!empty($taxs)): ?>
        <span style="color:#888; font-size:11px;">
            <?php echo __('Restricted to taxonomies: %s', h(implode(', ', $taxs))); ?>.
        </span>
    <?php endif; ?>
</div>
