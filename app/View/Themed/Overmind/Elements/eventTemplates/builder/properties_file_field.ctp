<h4 class="h6 fw-semibold mb-3"><?= __('File field properties') ?></h4>
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
        <input type="checkbox" id="et-prop-file-mandatory"
               class="form-check-input"
               :checked="getField('mandatory')"
               @change="setField('mandatory', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-file-mandatory">
            <?= __('Mandatory') ?>
        </label>
    </div>
    <div class="form-check">
        <input type="checkbox" id="et-prop-file-repeatable"
               class="form-check-input"
               :checked="getField('repeatable')"
               @change="setField('repeatable', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-file-repeatable">
            <?= __('Repeatable (user can upload multiple files)') ?>
        </label>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Store uploaded files as') ?>
    </label>
    <select class="form-select form-select-sm bg-light"
            :value="getField('as')"
            @change="setField('as', $event.target.value)">
        <option value="attachment">
            <?= __('attachment — general-purpose file attribute') ?>
        </option>
        <option value="malware-sample">
            <?= __('malware-sample — encrypted / quarantined sample') ?>
        </option>
    </select>
</div>
