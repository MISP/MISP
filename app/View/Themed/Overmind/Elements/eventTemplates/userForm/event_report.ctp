<?php
    $id = isset($element['id']) ? (string)$element['id'] : '';
    $label = isset($element['label']) ? (string)$element['label'] : $id;
    $help = isset($element['help']) ? (string)$element['help'] : '';
    $mandatory = !empty($element['mandatory']);
    $defaultContent = isset($element['default_content']) ? (string)$element['default_content'] : '';
?>
<div class="et-field et-event-report-field mb-3"
     data-et-element-id="<?= h($id) ?>"
     data-et-element-type="event_report"
     data-et-mandatory="<?= $mandatory ? '1' : '0' ?>">
    <label for="et-input-<?= h($id) ?>" class="form-label fw-semibold mb-1">
        <?= h($label) ?>
        <?php if ($mandatory): ?>
            <span class="text-danger" title="<?= __('Mandatory') ?>">*</span>
        <?php endif; ?>
        <span class="text-muted small fw-normal">
            (<?= __('event report') ?>)
        </span>
    </label>
    <?php if ($help !== ''): ?>
        <div class="et-help text-muted small mb-1">
            <?= $this->EventTemplateMarkdown->render($help) ?>
        </div>
    <?php endif; ?>
    <textarea id="et-input-<?= h($id) ?>"
              class="form-control bg-light et-value"
              data-et-path="<?= h($id) ?>"
              rows="12"><?= h($defaultContent) ?></textarea>
</div>
