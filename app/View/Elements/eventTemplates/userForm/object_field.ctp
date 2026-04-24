<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $repeatable = !empty($element['repeatable']);
    $spec = isset($objectRelationSpecs[$id]) ? $objectRelationSpecs[$id] : null;
?>
<div class="et-field et-object-field" data-et-element-id="<?php echo h($id); ?>"
     data-et-element-type="object_field" data-et-mandatory="<?php echo $mandatory ? '1' : '0'; ?>"
     data-et-repeatable="<?php echo $repeatable ? '1' : '0'; ?>"
     style="margin:14px 0; padding:10px; border:1px solid #e1e1e1; border-radius:4px; background:#fafafa;">
    <div style="font-weight:600; margin-bottom:4px;">
        <?php echo h($label); ?>
        <?php if ($mandatory): ?><span class="red" title="<?php echo __('Mandatory'); ?>">*</span><?php endif; ?>
        <?php if (!empty($spec) && !$spec['missing']): ?>
            <span style="color:#888; font-size:11px; font-weight:normal;">
                <?php echo h($spec['meta_category'] . ' · v' . $spec['found_version']); ?>
            </span>
        <?php endif; ?>
    </div>
    <?php if ($help !== ''): ?>
        <div class="et-help" style="color:#666; font-size:12px; margin-bottom:6px;">
            <?php echo $this->EventTemplateMarkdown->render($help); ?>
        </div>
    <?php endif; ?>

    <?php if (empty($spec) || !empty($spec['missing'])): ?>
        <div class="alert alert-error">
            <?php echo __('Referenced object template is not installed on this instance (uuid %s at pinned version %s).',
                !empty($spec['uuid']) ? h($spec['uuid']) : '?',
                !empty($spec['pinned_version']) ? (int)$spec['pinned_version'] : '?'
            ); ?>
        </div>
    <?php else: ?>
        <div class="et-entries">
            <div class="et-entry" style="border-top:1px dashed #ddd; padding-top:6px; margin-top:6px; position:relative;">
                <?php if ($repeatable): ?>
                    <button type="button" class="btn btn-mini et-remove-entry"
                            style="position:absolute; right:0; top:6px; display:none;">×</button>
                <?php endif; ?>
                <?php foreach ($spec['relations'] as $rel): ?>
                    <?php
                        $relation = $rel['object_relation'];
                        $relType = $rel['type'];
                        $relDesc = $rel['description'];
                    ?>
                    <div class="control-group" style="margin-bottom:4px;">
                        <label style="font-weight:500; font-size:12px;">
                            <?php echo h($relation); ?>
                            <span style="color:#888; font-size:11px;">(<?php echo h($relType); ?>)</span>
                        </label>
                        <?php if ($relDesc !== ''): ?>
                            <div style="color:#888; font-size:11px; margin-bottom:2px;">
                                <?php echo h($relDesc); ?>
                            </div>
                        <?php endif; ?>
                        <input type="text" class="input-block-level et-value"
                               data-et-path="<?php echo h($id . '.' . $relation); ?>">
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php if ($repeatable): ?>
            <button type="button" class="btn btn-mini et-add-entry" style="margin-top:6px;">
                + <?php echo __('Add another instance'); ?>
            </button>
        <?php endif; ?>
    <?php endif; ?>
</div>
