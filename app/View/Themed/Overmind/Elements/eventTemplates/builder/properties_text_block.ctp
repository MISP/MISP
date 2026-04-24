<h4 class="h6 fw-semibold mb-3"><?= __('Text block properties') ?></h4>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Stable id') ?></label>
    <input type="text"
           class="form-control form-control-sm bg-light" disabled
           :value="getField('id')">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Content (Markdown)') ?></label>
    <textarea rows="6"
              class="form-control form-control-sm bg-light"
              :value="getField('content')"
              @input="setField('content', $event.target.value)"></textarea>
    <div class="form-text small">
        <?= __('Rendered inline in the user form. Supports Markdown; raw HTML is stripped.') ?>
    </div>
</div>
