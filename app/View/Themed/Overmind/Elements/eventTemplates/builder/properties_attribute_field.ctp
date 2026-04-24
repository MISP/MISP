<?php
    $categories = isset($attributeCategoryDefinitions)
        ? $attributeCategoryDefinitions
        : [];
?>
<h4 class="h6 fw-semibold mb-3"><?= __('Attribute field properties') ?></h4>
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
        <input type="checkbox" id="et-prop-attr-mandatory"
               class="form-check-input"
               :checked="getField('mandatory')"
               @change="setField('mandatory', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-attr-mandatory">
            <?= __('Mandatory (user must fill this field)') ?>
        </label>
    </div>
    <div class="form-check">
        <input type="checkbox" id="et-prop-attr-repeatable"
               class="form-check-input"
               :checked="getField('repeatable')"
               @change="setField('repeatable', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-attr-repeatable">
            <?= __('Repeatable (user can add multiple values)') ?>
        </label>
    </div>
</div>
<hr>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('MISP category') ?> <span class="text-danger">*</span>
    </label>
    <select class="form-select form-select-sm bg-light"
            :value="getField('misp.category')"
            @change="setField('misp.category', $event.target.value)">
        <option value=""><?= __('— select —') ?></option>
        <?php foreach (array_keys($categories) as $cat): ?>
            <option value="<?= h($cat) ?>"><?= h($cat) ?></option>
        <?php endforeach; ?>
    </select>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('MISP type') ?> <span class="text-danger">*</span>
    </label>
    <select class="form-select form-select-sm bg-light"
            :value="getField('misp.type')"
            @change="setField('misp.type', $event.target.value)">
        <option value=""
                x-text="getField('misp.category')
                    ? '<?= __('— select a type —') ?>'
                    : '<?= __('— select a category first —') ?>'"></option>
        <template x-for="t in attributeTypeOptions" :key="t">
            <option :value="t" x-text="t"
                    :selected="getField('misp.type') === t"></option>
        </template>
    </select>
    <div class="form-text small">
        <?= __('Types are filtered to the selected category.') ?>
    </div>
</div>
<div class="mb-3">
    <div class="form-check">
        <input type="checkbox" id="et-prop-attr-to-ids"
               class="form-check-input"
               :checked="getField('misp.to_ids_default')"
               @change="setField('misp.to_ids_default', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-attr-to-ids">
            <?= __('Default to_ids = true') ?>
        </label>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Comment template') ?></label>
    <input type="text"
           class="form-control form-control-sm bg-light"
           :value="getField('misp.comment_template')"
           @input="setField('misp.comment_template', $event.target.value)">
    <div class="form-text small">
        <?= __('Pre-filled on the attribute\'s comment field when the user submits.') ?>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Default value') ?></label>
    <input type="text"
           class="form-control form-control-sm bg-light"
           :value="getField('misp.default_value')"
           @input="setField('misp.default_value', $event.target.value)">
</div>
