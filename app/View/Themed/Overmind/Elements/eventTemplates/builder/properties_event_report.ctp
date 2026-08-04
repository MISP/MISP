<h4 class="h6 fw-semibold mb-3"><?= __('Event report properties') ?></h4>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Stable id') ?></label>
    <input type="text"
           class="form-control form-control-sm bg-light" disabled
           :value="getField('id')">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Label') ?> <span class="text-danger">*</span>
    </label>
    <input type="text"
           class="form-control form-control-sm bg-light"
           :value="getField('label')"
           @input="setField('label', $event.target.value)">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Help text (Markdown)') ?></label>
    <textarea rows="2"
              class="form-control form-control-sm bg-light"
              :value="getField('help')"
              @input="setField('help', $event.target.value)"></textarea>
</div>
<div class="mb-3">
    <div class="form-check">
        <input type="checkbox" id="et-prop-event-report-mandatory"
               class="form-check-input"
               :checked="getField('mandatory')"
               @change="setField('mandatory', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-event-report-mandatory">
            <?= __('Mandatory') ?>
        </label>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Default content (Markdown)') ?></label>
    <textarea rows="6"
              class="form-control form-control-sm bg-light"
              :value="getField('default_content')"
              @input="setField('default_content', $event.target.value)"></textarea>
    <div class="form-text small">
        <?= __('Pre-fills the report body the user starts editing from. The filled value is saved as an EventReport row attached to the new event.') ?>
    </div>
</div>
