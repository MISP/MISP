<h4 class="h6 fw-semibold mb-3"><?= __('Object field properties') ?></h4>
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
        <input type="checkbox" id="et-prop-obj-mandatory"
               class="form-check-input"
               :checked="getField('mandatory')"
               @change="setField('mandatory', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-obj-mandatory">
            <?= __('Mandatory') ?>
        </label>
    </div>
    <div class="form-check">
        <input type="checkbox" id="et-prop-obj-repeatable"
               class="form-check-input"
               :checked="getField('repeatable')"
               @change="setField('repeatable', $event.target.checked)">
        <label class="form-check-label small" for="et-prop-obj-repeatable">
            <?= __('Repeatable (user can add multiple object instances)') ?>
        </label>
    </div>
</div>
<hr>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Object template') ?> <span class="text-danger">*</span>
    </label>
    <div class="d-flex align-items-center gap-2 flex-wrap">
        <button type="button" class="btn btn-sm btn-outline-secondary"
                @click="openObjectTemplatePicker">
            <i class="fas fa-search me-1"></i><?= __('Choose…') ?>
        </button>
        <span class="et-ot-picker-current small fw-semibold">
            <em class="text-muted" x-show="!getField('object_template.uuid')">
                <?= __('(none selected)') ?>
            </em>
            <span x-show="getField('object_template.uuid')"
                  x-text="getField('object_template.name')"></span>
            <span class="text-muted ms-1"
                  x-show="getField('object_template.pinned_version')"
                  x-text="'v' + getField('object_template.pinned_version')"></span>
            <span class="text-muted ms-1"
                  x-show="currentObjectTemplateMeta()"
                  x-text="currentObjectTemplateMeta()"></span>
        </span>
    </div>
    <div class="form-text small">
        <?= __('Opens a searchable list of active object templates on this instance.') ?>
    </div>
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Current uuid') ?></label>
    <input type="text"
           class="form-control form-control-sm bg-light" readonly
           :value="getField('object_template.uuid')">
</div>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1"><?= __('Pinned version') ?></label>
    <input type="text"
           class="form-control form-control-sm bg-light" readonly
           :value="getField('object_template.pinned_version')">
</div>
<hr>
<div class="mb-3">
    <label class="form-label fw-semibold small mb-1">
        <?= __('Relations to include in the user form') ?>
    </label>
    <div class="et-relations-panel">
        <div class="et-relations-empty text-muted fst-italic small py-2"
             x-show="!getField('object_template.uuid')">
            <?= __('Pick an object template above to choose which relations the user will see.') ?>
        </div>
        <div class="et-relations-controls small mb-1"
             x-show="getField('object_template.uuid')">
            <a href="#" @click.prevent="selectAllRelations">
                <?= __('Select all') ?>
            </a>
            <span class="text-muted mx-1">·</span>
            <a href="#" @click.prevent="selectNoRelations">
                <?= __('Select none') ?>
            </a>
            <span class="text-muted ms-2">
                <?= __('Empty selection = show all relations (object-template default).') ?>
            </span>
        </div>
        <div class="et-relations-list border rounded"
             x-show="getField('object_template.uuid')"
             style="max-height:260px; overflow-y:auto;">
            <div class="text-muted p-2"
                 x-show="objectTemplateRelationsLoading">
                <?= __('Loading relations…') ?>
            </div>
            <div class="text-muted p-2"
                 x-show="!objectTemplateRelationsLoading
                         && objectTemplateRelations.length === 0">
                <?= __('This object template has no relations.') ?>
            </div>
            <template x-for="rel in objectTemplateRelations"
                      :key="rel.object_relation">
                <label :title="rel.description">
                    <input type="checkbox"
                           :value="rel.object_relation"
                           :checked="isRelationSelected(rel.object_relation)"
                           @change="toggleRelation(rel.object_relation, $event.target.checked)">
                    <span class="et-rel-name" x-text="rel.object_relation"></span>
                    <span class="et-rel-type" x-text="rel.type"></span>
                </label>
            </template>
        </div>
    </div>
</div>
