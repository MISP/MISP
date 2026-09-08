<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $multiple = !empty($element['multiple']);
    $taxs = isset($element['restrict_taxonomies']) && is_array($element['restrict_taxonomies'])
        ? $element['restrict_taxonomies']
        : [];
?>


<div class="et-field et-tag-field mb-3"
     data-et-element-id="<?= h($id) ?>"
     data-et-element-type="tag_field"
     data-et-mandatory="<?= $mandatory ? '1' : '0' ?>"
     data-et-multiple="<?= $multiple ? '1' : '0' ?>"
     data-et-restrict-taxonomies="<?= h(JsonTool::encode($taxs)) ?>">
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
    <select class="et-tag-select"
            placeholder="<?= h($multiple ? __('Search tags to add…') : __('Search a tag…')) ?>">
    </select>
    <div class="mt-2 d-flex flex-wrap et-tag-selected"></div>
    <div class="text-muted small fst-italic et-tag-selected-empty">
        <?= __('No tag selected.') ?>
    </div>
    <input type="hidden" class="et-value"
           data-et-path="<?= h($id) ?>"
           data-et-csv="1">
    <?php if (!empty($taxs)): ?>
        <div class="text-muted small mt-1">
            <?= __('Restricted to taxonomies: %s', h(implode(', ', $taxs))) ?>.
        </div>
    <?php endif; ?>
</div>
