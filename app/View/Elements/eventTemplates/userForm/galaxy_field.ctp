<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $multiple = !empty($element['multiple']);
    $galaxyTypes = isset($element['restrict_galaxy_types']) && is_array($element['restrict_galaxy_types'])
        ? $element['restrict_galaxy_types']
        : array();
?>
<div class="et-field et-galaxy-field" data-et-element-id="<?php echo h($id); ?>"
     data-et-element-type="galaxy_field" data-et-mandatory="<?php echo $mandatory ? '1' : '0'; ?>"
     data-et-multiple="<?php echo $multiple ? '1' : '0'; ?>"
     data-et-restrict-galaxy-types="<?php echo h(JsonTool::encode($galaxyTypes)); ?>"
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
    <input type="text" class="input-block-level et-value"
           data-et-path="<?php echo h($id); ?>"
           data-et-csv="1"
           placeholder="<?php
               echo $multiple
                   ? __('Comma-separated galaxy cluster values')
                   : __('A single galaxy cluster value');
           ?>">
    <span style="color:#888; font-size:11px;">
        <?php if (!empty($galaxyTypes)): ?>
            <?php echo __('Restricted to galaxy types: %s', h(implode(', ', $galaxyTypes))); ?>.
        <?php endif; ?>
        <?php echo __('Inline picker integration lands in the next commit.'); ?>
    </span>
</div>
