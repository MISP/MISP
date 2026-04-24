<h4 class="h6 fw-semibold mb-3"><?= __('Object reference properties') ?></h4>
<div class="alert alert-info py-2 px-3 small mb-3">
    <?= __('Object references are not user-facing; they materialise a relationship between two object fields when the event is created.') ?>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Stable id') ?></label>
    <input type="text"
           class="form-control form-control-sm bg-light" disabled
           :value="getField('id')">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('From (source object field)') ?> <span class="text-danger">*</span>
    </label>
    <select class="form-select form-select-sm bg-light"
            :value="getField('from')"
            @change="setField('from', $event.target.value)">
        <option value=""><?= __('— select —') ?></option>
        <template x-for="of in objectFieldChoices" :key="of.id">
            <option :value="of.id"
                    x-text="of.label + ' (' + of.id + ')'"
                    :selected="getField('from') === of.id"></option>
        </template>
    </select>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('To (target object field)') ?> <span class="text-danger">*</span>
    </label>
    <select class="form-select form-select-sm bg-light"
            :value="getField('to')"
            @change="setField('to', $event.target.value)">
        <option value=""><?= __('— select —') ?></option>
        <template x-for="of in objectFieldChoices" :key="of.id">
            <option :value="of.id"
                    x-text="of.label + ' (' + of.id + ')'"
                    :selected="getField('to') === of.id"></option>
        </template>
    </select>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Relationship type') ?> <span class="text-danger">*</span>
    </label>
    <input type="text"
           class="form-control form-control-sm bg-light"
           placeholder="has-attachment"
           :value="getField('relationship_type')"
           @input="setField('relationship_type', $event.target.value)">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Comment') ?></label>
    <input type="text"
           class="form-control form-control-sm bg-light"
           :value="getField('comment')"
           @input="setField('comment', $event.target.value)">
</div>
