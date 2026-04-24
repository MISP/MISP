<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $multiple = !empty($element['multiple']);
    $galaxyTypes = isset($element['restrict_galaxy_types']) && is_array($element['restrict_galaxy_types'])
        ? $element['restrict_galaxy_types']
        : [];
?>
<div class="et-field et-galaxy-field mb-3"
     data-et-element-id="<?= h($id) ?>"
     data-et-element-type="galaxy_field"
     data-et-mandatory="<?= $mandatory ? '1' : '0' ?>"
     data-et-multiple="<?= $multiple ? '1' : '0' ?>"
     data-et-restrict-galaxy-types="<?= h(JsonTool::encode($galaxyTypes)) ?>">
    <label class="form-label fw-semibold mb-1">
        <?= h($label) ?>
        <?php if ($mandatory): ?>
            <span class="text-danger">*</span>
        <?php endif; ?>
    </label>
    <?php if ($help !== ''): ?>
        <div class="et-help text-muted small mb-1">
            <?= $this->EventTemplateMarkdown->render($help) ?>
        </div>
    <?php endif; ?>
    <input type="text"
           class="form-control bg-light et-value"
           data-et-path="<?= h($id) ?>"
           data-et-csv="1"
           placeholder="<?=
               $multiple
                   ? __('Comma-separated galaxy cluster values')
                   : __('A single galaxy cluster value')
           ?>">
    <div class="text-muted small mt-1">
        <?php if (!empty($galaxyTypes)): ?>
            <?= __('Restricted to galaxy types: %s', h(implode(', ', $galaxyTypes))) ?>.
        <?php endif; ?>
        <?= __('Inline picker integration lands in Phase 3.4.') ?>
    </div>
</div>
