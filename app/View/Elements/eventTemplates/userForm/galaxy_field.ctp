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
    <div style="display:flex; gap:6px; align-items:center;">
        <input type="text" class="input-block-level et-value"
               data-et-path="<?php echo h($id); ?>"
               data-et-csv="1"
               style="flex:1; margin-bottom:0;"
               placeholder="<?php
                   echo $multiple
                       ? __('Comma-separated galaxy cluster values (e.g. APT41, FIN7)')
                       : __('A single galaxy cluster value (e.g. APT41)');
               ?>">
        <?php if (!empty($galaxyTypes)): ?>
            <button type="button" class="btn"
                    data-et-open-galaxy-picker="<?php echo h($id); ?>">
                <i class="fa fa-globe"></i> <?php echo __('Choose…'); ?>
            </button>
        <?php endif; ?>
    </div>
    <?php if (!empty($galaxyTypes)): ?>
        <span style="color:#888; font-size:11px;">
            <?php echo __('Restricted to galaxy types: %s', h(implode(', ', $galaxyTypes))); ?>.
        </span>
    <?php else: ?>
        <span style="color:#888; font-size:11px;">
            <?php echo __('No galaxy-type restriction set on this field; type values manually.'); ?>
        </span>
    <?php endif; ?>
</div>
