<h4 class="h6 fw-semibold mb-3"><?= __('Text block properties') ?></h4>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Stable id') ?></label>
    <input type="text" data-et-field="id" class="form-control form-control-sm bg-light" disabled>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Content (Markdown)') ?></label>
    <textarea data-et-field="content" rows="6"
              class="form-control form-control-sm bg-light"></textarea>
    <div class="form-text small">
        <?= __('Rendered inline in the user form. Supports Markdown; raw HTML is stripped.') ?>
    </div>
</div>
