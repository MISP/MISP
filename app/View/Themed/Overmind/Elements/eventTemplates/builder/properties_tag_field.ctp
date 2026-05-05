<h4 class="h6 fw-semibold mb-3"><?= __('Tag field properties') ?></h4>
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
        <input type="checkbox" id="et-prop-tag-mandatory"
               class="form-check-input"
               :checked="getField('mandatory')"
               @change="setField('mandatory', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-tag-mandatory">
            <?= __('Mandatory') ?>
        </label>
    </div>
    <div class="form-check">
        <input type="checkbox" id="et-prop-tag-multiple"
               class="form-check-input"
               :checked="getField('multiple')"
               @change="setField('multiple', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-tag-multiple">
            <?= __('Allow multiple tags') ?>
        </label>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Restrict to taxonomies') ?>
    </label>
    <select multiple
            x-init="initMultipicker($el, 'taxonomies', 'restrict_taxonomies', '<?= __('Select taxonomies…') ?>')"
            class="form-select form-select-sm bg-light"></select>
    <div class="form-text small">
        <?= __('Empty selection = the user can pick any tag. Otherwise restricted to tags from the chosen taxonomies.') ?>
    </div>
</div>
