<?php
$tpl = $data['EventTemplate'] ?? [];
$templateId = (int)($tpl['id'] ?? 0);

$definitionJson = is_array($tpl['definition'] ?? null)
    ? JsonTool::encode($tpl['definition'], true)
    : (string)($tpl['definition'] ?? '');
?>
<div class="card mb-3 shadow-sm">
    <div class="card-header bg-white fw-semibold d-flex justify-content-between align-items-center flex-wrap gap-2">
        <span>
            <i class="fas fa-code me-2"></i><?= __('Definition (JSON)') ?>
        </span>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-sm btn-outline-secondary"
                    data-json="<?= h($definitionJson) ?>"
                    onclick="copyValueToClipboard(this.dataset.json, '<?= h(__('Definition copied to clipboard')) ?>')">
                <i class="fas fa-copy me-1"></i><?= __('Copy') ?>
            </button>
            <a class="btn btn-sm btn-outline-secondary"
               href="<?= h($baseurl . '/event_templates/export/' . $templateId) ?>">
                <i class="fas fa-download me-1"></i><?= __('Download export') ?>
            </a>
        </div>
    </div>
    <div class="card-body p-0">
        <pre class="mb-0 p-3 bg-light"
             style="max-height:600px; overflow:auto; font-size:.8rem;"><?= h($definitionJson) ?></pre>
    </div>
</div>
