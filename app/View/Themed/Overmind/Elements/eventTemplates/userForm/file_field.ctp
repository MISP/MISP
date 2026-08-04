<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $repeatable = !empty($element['repeatable']);
    $as = isset($element['as']) ? (string)$element['as'] : 'attachment';
?>
<div class="et-field et-file-field mb-3"
     data-et-element-id="<?= h($id) ?>"
     data-et-element-type="file_field"
     data-et-mandatory="<?= $mandatory ? '1' : '0' ?>"
     data-et-repeatable="<?= $repeatable ? '1' : '0' ?>"
     data-et-file-as="<?= h($as) ?>">
    <label class="form-label fw-semibold mb-1">
        <?= h($label) ?>
        <?php if ($mandatory): ?>
            <span class="text-danger">*</span>
        <?php endif; ?>
        <span class="text-muted small fw-normal">
            (<?= __('stored as %s', h($as)) ?>)
        </span>
    </label>
    <?php if ($help !== ''): ?>
        <div class="et-help text-muted small mb-1">
            <?= $this->EventTemplateMarkdown->render($help) ?>
        </div>
    <?php endif; ?>

    <input type="file"
           class="form-control bg-light et-file-input"
           <?php if ($repeatable): ?>multiple<?php endif; ?>
           data-et-file-target="<?= h($id) ?>">
    <div class="et-file-list text-muted small mt-2"
         data-et-file-list-for="<?= h($id) ?>"></div>
    <?php if ($as === 'malware-sample'): ?>
        <div class="text-muted small mt-1">
            <?= __('Files uploaded here are server-side zipped and password-encrypted as MISP malware samples before storage.') ?>
        </div>
    <?php endif; ?>
</div>
