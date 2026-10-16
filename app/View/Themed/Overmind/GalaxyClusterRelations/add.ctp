<?php

$isEdit = $this->request->params['action'] === 'edit';
$relation = $this->request->data['GalaxyClusterRelation'] ?? [];

$currentDistribution = isset($relation['distribution'])
    ? (int)$relation['distribution']
    : (int)($initialDistribution ?? 0);

/* getExistingRelationships() returns a plain list — a select wants a map. The
 * picker still creates a type of its own, so the list is a suggestion, not a
 * closed vocabulary. */
$relationshipTypes = array_combine($existingRelations, $existingRelations);
$currentType = $relation['referenced_galaxy_cluster_type'] ?? null;
if (!empty($currentType) && !isset($relationshipTypes[$currentType])) {
    $relationshipTypes[$currentType] = $currentType;
}
natcasesort($relationshipTypes);

echo $this->Form->create('GalaxyClusterRelation', [
    'id' => 'galaxyClusterRelationForm',
    'novalidate' => true,
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'galaxy',
    'eyebrow' => __('Galaxy Cluster Relationships'),
    'title' => $isEdit
        ? __('Edit Galaxy Cluster Relationship')
        : __('Add Galaxy Cluster Relationship'),
    'description' => __('Relationships link two galaxy clusters together and explain the context of their connection.'),
    'icon' => 'fas fa-diagram-project',
    'isEdit' => $isEdit,
]);
?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4 px-2">

        <!-- ── SOURCE → TARGET ─────────────────────────────────── -->
        <div class="row g-3">

            <div class="col-12 col-md">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'galaxy',
                    'label' => __('Source Cluster'),
                    'required' => true,
                ]) ?>
                <?php if (!empty($sourceCluster) && !$isEdit): ?>
                    <?= $this->Form->hidden('galaxy_cluster_uuid', ['id' => 'GalaxyClusterRelationSourceUuid']) ?>
                    <div class="py-1">
                        <?= $this->TagChip->cluster([
                            'id' => $sourceCluster['id'],
                            'value' => $sourceCluster['value'],
                            'galaxy' => $sourceCluster['Galaxy']['name'] ?? '',
                            'galaxy_id' => $sourceCluster['galaxy_id'],
                            'icon' => $sourceCluster['Galaxy']['icon'] ?? null,
                            'description' => $sourceCluster['description'] ?? null,
                        ]) ?>
                    </div>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => __('Saving unpublishes this cluster.'),
                        'icon' => 'fas fa-circle-info mt-1',
                    ]) ?>
                <?php else: ?>
                <?php
                $sourceOptions = [
                    'id' => 'GalaxyClusterRelationSourceUuid',
                    'class' => 'form-control font-monospace'
                        . ($isEdit ? ' bg-body-secondary' : ''),
                    'style' => 'border-color:var(--misp-field-line, #d8dde3);',
                    'placeholder' => __('UUID of the cluster the relationship starts from'),
                    'autocomplete' => 'off',
                ];
                if ($isEdit) {
                    $sourceOptions['readonly'] = true;
                } else {
                    $sourceOptions['data-om-required'] = 'true';
                }
                echo $this->Form->text('galaxy_cluster_uuid', $sourceOptions);
                ?>
                <div class="invalid-feedback">
                    <?= __('A source cluster UUID is required.') ?>
                </div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => $isEdit
                        ? __('The source cluster of an existing relationship cannot be changed.')
                        : __('You need edit rights on this cluster — saving also unpublishes it.'),
                    'icon' => $isEdit ? 'fas fa-lock mt-1' : 'fas fa-circle-info mt-1',
                ]) ?>
                <?php endif; ?>
            </div>

            <div class="col-md-auto d-none d-md-flex align-items-center justify-content-center pt-1">
                <span class="d-inline-flex align-items-center justify-content-center rounded-circle text-galaxy"
                      style="width:2rem; height:2rem; background:rgba(var(--bs-galaxy-rgb), .12);">
                    <i class="fas fa-arrow-right-long"></i>
                </span>
            </div>

            <div class="col-12 col-md">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'galaxy',
                    'label' => __('Target Cluster'),
                    'required' => true,
                ]) ?>
                <?php
                $targetUuid = $relation['referenced_galaxy_cluster_uuid'] ?? '';
                $targetOptions = $targetUuid === '' ? [] : [$targetUuid => $targetCluster['value'] ?? $targetUuid];
                ?>
                <?= $this->Form->select('referenced_galaxy_cluster_uuid', $targetOptions, [
                    'id' => 'GalaxyClusterRelationTargetUuid',
                    'class' => 'form-select',
                    'empty' => '',
                    'value' => $targetUuid,
                    'data-om-required' => 'true',
                    'data-cluster-search' => $baseurl . '/galaxy_clusters/pickerSearch?value=uuid',
                    'data-exclude' => $sourceCluster['uuid'] ?? '',
                ]) ?>
                <div class="invalid-feedback">
                    <?= __('A target cluster is required.') ?>
                </div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('Type a cluster name to search any galaxy, or paste its UUID.'),
                ]) ?>
            </div>

        </div>

        <!-- ── RELATIONSHIP TYPE ───────────────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'galaxy',
                'label' => __('Relationship Type'),
                'required' => true,
            ]) ?>
            <?= $this->Form->select('referenced_galaxy_cluster_type', $relationshipTypes, [
                'id' => 'GalaxyClusterRelationType',
                'class' => 'form-select',
                'empty' => __('e.g. is-similar'),
                'value' => $currentType,
                'data-om-required' => 'true',
            ]) ?>
            <div class="invalid-feedback">
                <?= __('A relationship type is required.') ?>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Pick one of the types already in use, or type your own and press enter to create it.'),
            ]) ?>
        </div>

        <!-- ── DISTRIBUTION / SHARING GROUP ────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/distribution_field', [
                'accent' => 'galaxy',
                'levels' => $distributionLevels,
                'value' => $currentDistribution,
                'sharingGroups' => $sharingGroups,
                'showSg' => true,
                'sgId' => 'GalaxyClusterRelationSharingGroupId',
                'sgEmpty' => empty($sharingGroups)
                    ? __('No sharing group available')
                    : __('Select a sharing group…'),
            ]) ?>
        </div>

        <!-- ── TAGS ────────────────────────────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'galaxy',
                'label' => __('Tags'),
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/tag_picker_field', [
                'field' => 'GalaxyClusterRelation.tags',
                'uid' => 'galaxy-cluster-relation-tags',
                'categories' => [
                    'all' => [
                        'label' => __('All Tags'),
                        'tags' => $pickerAllTags ?? [],
                    ],
                    'custom' => [
                        'label' => __('Custom Tags'),
                        'tags' => $pickerCustomTags ?? [],
                    ],
                ],
                'selected' => $currentTags ?? [],
                'emptyText' => __('No tags on this relationship.'),
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Qualify the relationship, e.g. how likely it is.'),
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'galaxy',
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($relation['id'])
            ? [['label' => __('Relationship'), 'id' => $relation['id']]]
            : [],
        'hint' => __('The source cluster is unpublished when the relationship is saved.'),
        'submit' => [
            'label' => $isEdit ? __('Save Changes') : __('Add Relationship'),
        ],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var form = document.getElementById('galaxyClusterRelationForm');
    if (!form) {
        return;
    }

    /* The relationship type is free text with suggestions: initTomSelect()
       binds `select.tom-select` with create:false, which would close the
       vocabulary, so this one is wired here instead. */
    var typeEl = document.getElementById('GalaxyClusterRelationType');
    if (typeEl && !typeEl.tomselect && typeof TomSelect !== 'undefined') {
        new TomSelect(typeEl, {
            create: true,
            persist: false,
            createOnBlur: true,
            maxOptions: null,
            placeholder: <?= json_encode(__('e.g. is-similar')) ?>
        });
    }

    var targetEl = document.getElementById('GalaxyClusterRelationTargetUuid');
    if (targetEl && !targetEl.tomselect && typeof TomSelect !== 'undefined') {
        var uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        var exclude = targetEl.getAttribute('data-exclude');
        var searchUrl = targetEl.getAttribute('data-cluster-search');
        var esc = function (s) {
            var d = document.createElement('div');
            d.textContent = s == null ? '' : String(s);
            return d.innerHTML;
        };
        var row = function (item) {
            return '<div>' + esc(item.text)
                + (item.galaxy ? '<span class="text-muted small ms-2">' + esc(item.galaxy) + '</span>' : '')
                + '</div>';
        };
        new TomSelect(targetEl, {
            maxItems: 1,
            maxOptions: null,
            loadThrottle: 250,
            searchField: ['text', 'galaxy'],
            placeholder: <?= json_encode(__('Search a cluster by name')) ?>,
            create: function (input) {
                return uuidRe.test(input.trim()) ? { value: input.trim(), text: input.trim() } : false;
            },
            createFilter: function (input) { return uuidRe.test(input.trim()); },
            shouldLoad: function (query) { return query.trim().length >= 2 && !uuidRe.test(query.trim()); },
            load: function (query, callback) {
                fetch(searchUrl + '&q=' + encodeURIComponent(query.trim()), {
                    headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
                    credentials: 'same-origin'
                })
                    .then(function (r) { return r.ok ? r.json() : []; })
                    .then(function (rows) {
                        callback(rows.filter(function (r) { return r.value !== exclude; }).map(function (r) {
                            return { value: r.value, text: r.label, galaxy: (r.style && r.style.galaxy) || '' };
                        }));
                    })
                    .catch(function () { callback(); });
            },
            render: {
                option: row,
                item: row,
                option_create: function (data) {
                    return '<div class="create">' + <?= json_encode(__('Use UUID')) ?> + ' <code>' + esc(data.input) + '</code></div>';
                },
                no_results: function () {
                    return '<div class="no-results text-muted">' + <?= json_encode(__('No cluster matches')) ?> + '</div>';
                }
            }
        });
    }

    /* $this->Form->create() is novalidate — the browser bubbles do not match
       the theme — so the required fields are checked here. A failed POST
       re-renders this template without a layout, which is worth avoiding. */
    var required = Array.prototype.slice.call(
        form.querySelectorAll('[data-om-required]')
    );

    var flag = function (el, invalid) {
        var target = el.tomselect ? el.tomselect.wrapper : el;
        target.classList.toggle('is-invalid', invalid);
    };

    required.forEach(function (el) {
        var clear = function () {
            if (String(el.value || '').trim()) {
                flag(el, false);
            }
        };
        el.addEventListener('input', clear);
        el.addEventListener('change', clear);
    });

    form.addEventListener('submit', function (e) {
        var firstInvalid = null;
        required.forEach(function (el) {
            var empty = !String(el.value || '').trim();
            flag(el, empty);
            if (empty && !firstInvalid) {
                firstInvalid = el;
            }
        });
        if (firstInvalid) {
            e.preventDefault();
            e.stopPropagation();
            if (firstInvalid.tomselect) {
                firstInvalid.tomselect.focus();
            } else {
                firstInvalid.focus();
            }
        }
    });
})();
</script>
