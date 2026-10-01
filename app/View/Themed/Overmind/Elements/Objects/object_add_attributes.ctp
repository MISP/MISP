<?php
/*
 * One attribute row of the object add/edit form.
 *
 * The row is cloned client-side from a <template> by the palette, so every id
 * and name it carries has to stay derivable from $k — initObjectForm()
 * reindexes them.
 */
if (empty($enabledRows)) $enabledRows = [];
if (empty($action))      $action      = 'add';

// A clone source must start empty whatever the element it was built from carries.
if (!empty($blank)) {
    unset($element['value'], $element['comment'], $element['uuid']);
}
$removable = !isset($removable) || $removable;

$isRequired = !empty($template['ObjectTemplate']['requirements']['required'])
    && in_array(
        $element['object_relation'],
        $template['ObjectTemplate']['requirements']['required'],
        true
    );

$idsOn    = !empty($element['to_ids']);
$corrOff  = !empty($element['disable_correlation']);
$corrDis  = in_array($element['type'], MispAttribute::NON_CORRELATING_TYPES, true);
$corrOn   = !$corrOff && !$corrDis;
$initDist = !empty($element['distribution'])
    ? (int)$element['distribution']
    : (int)$distributionData['initial'];
?>

<div id="row_<?= h($k) ?>"
     class="attribute_row ov-obj-row card mb-2 shadow-sm"
     data-row-index="<?= h($k) ?>"
     data-object-relation="<?= h($element['object_relation']) ?>"
     data-multiple="<?= empty($element['multiple']) ? '0' : '1' ?>">

    <!-- ── HEADER ──────────────────────────────────────────── -->
    <div class="card-header ov-obj-row-header d-flex align-items-start gap-2 py-2 px-3">

        <?= $this->Form->hidden('Attribute.' . $k . '.save', [
            'value' => 1,
            'id' => 'Attribute' . $k . 'Save',
        ]) ?>

        <!-- Hidden fields -->
        <?= $this->Form->input('Attribute.' . $k . '.object_relation', [
            'type' => 'hidden', 'value' => $element['object_relation'],
            'label' => false, 'div' => false,
        ]) ?>

        <?php if ($action === 'edit' && empty($blank)): ?>
        <?= $this->Form->input('Attribute.' . $k . '.uuid', [
            'type' => 'hidden',
            'value' => !empty($element['uuid']) ? $element['uuid'] : '',
            'label' => false, 'div' => false,
        ]) ?>
        <?php endif; ?>
        <?= $this->Form->input('Attribute.' . $k . '.type', [
            'type' => 'hidden', 'value' => $element['type'],
            'label' => false, 'div' => false,
        ]) ?>

        <!-- Name + type badge + required + description -->
        <div class="flex-fill min-w-0">
            <div class="d-flex align-items-center gap-2 flex-wrap">
                <span class="ov-obj-row-name text-uppercase">
                    <?= h(Inflector::humanize($element['object_relation'])) ?>
                </span>
                <?php if ($isRequired): ?>
                    <i class="fas fa-asterisk text-danger ov-obj-required"
                       title="<?= __('Required') ?>"></i>
                <?php endif; ?>
                <span class="badge rounded-pill bg-secondary fw-normal ov-obj-row-type">
                    <?= h($element['type']) ?>
                </span>
            </div>
            <?php if (!empty($element['description'])): ?>
            <div class="ov-obj-row-desc text-muted lh-sm mt-1">
                <?= h($element['description']) ?>
            </div>
            <?php endif; ?>
        </div>

        <?php if ($removable): ?>
            <button type="button"
                    class="btn btn-sm ov-obj-row-remove flex-shrink-0"
                    aria-label="<?= __('Remove this attribute') ?>"
                    title="<?= __('Remove this attribute') ?>">
                <i class="fas fa-trash"></i>
            </button>
        <?php endif; ?>

    </div>

    <!-- ── BODY: value field ───────────────────────────────── -->
    <div class="card-body py-2 px-3">
        <?= $this->element('Objects/object_value_field', [
            'element' => $element,
            'k'       => $k,
            'action'  => $action,
        ]) ?>
    </div>

    <!-- ── FOOTER: controls ────────────────────────────────── -->
    <div class="card-footer ov-obj-row-footer py-2 px-3 d-flex flex-wrap align-items-center gap-2">

        <!-- Category -->
        <?= $this->Form->select(
            'Attribute.' . $k . '.category',
            array_combine($element['categories'], $element['categories']),
            [
                'default' => $element['default_category'],
                'class'   => 'form-select form-select-sm ov-obj-row-select Attribute_category_select',
            ]
        ) ?>

        <!-- IDS toggle -->
        <label class="ov-obj-toggle ov-obj-toggle-ids<?= $idsOn ? ' is-on' : '' ?>"
               id="card-ids-<?= h($k) ?>"
               title="<?= __('Send to IDS') ?>">
            <?= $this->Form->input('Attribute.' . $k . '.to_ids', [
                'type'    => 'checkbox',
                'checked' => $idsOn,
                'label'   => false,
                'div'     => false,
                'class'   => 'ov-obj-toggle-input',
            ]) ?>
            <i class="fas fa-shield-halved"></i>
            <span><?= __('IDS') ?></span>
        </label>

        <!-- Correlate toggle. The checkbox is disable_correlation, so the tile is
             lit when it is *un*checked. -->
        <label class="ov-obj-toggle ov-obj-toggle-corr<?= $corrOn ? ' is-on' : '' ?><?= $corrDis ? ' is-locked' : '' ?>"
               id="card-corr-<?= h($k) ?>"
               title="<?= $corrDis ? __('This type never correlates') : __('Enable correlation') ?>">
            <?= $this->Form->input('Attribute.' . $k . '.disable_correlation', [
                'type'     => 'checkbox',
                'checked'  => $corrOff,
                'disabled' => $corrDis,
                'label'    => false,
                'div'      => false,
                'class'    => 'ov-obj-toggle-input',
            ]) ?>
            <i class="fas fa-link ov-toggle-on-icon"></i>
            <i class="fas fa-link-slash ov-toggle-off-icon"></i>
            <span><?= __('Correlate') ?></span>
        </label>

        <!-- Distribution + SG (pushed right) -->
        <div class="ms-auto d-flex align-items-center gap-2 flex-wrap">
            <span class="text-muted ov-obj-row-label"><?= __('Distrib.') ?></span>
            <?= $this->Form->select(
                'Attribute.' . $k . '.distribution',
                $distributionData['levels'],
                [
                    'class'   => 'form-select form-select-sm ov-obj-row-select Attribute_distribution_select',
                    'default' => $initDist,
                ]
            ) ?>

            <span class="ov-obj-sg-wrap<?= (int)$initDist === 4 ? '' : ' d-none' ?>">
                <?= $this->Form->select(
                    'Attribute.' . $k . '.sharing_group_id',
                    $distributionData['sgs'],
                    [
                        'class'  => 'form-select form-select-sm ov-obj-row-select Attribute_sharing_group_id_select',
                        'default' => !empty($element['sharing_group_id'])
                            ? $element['sharing_group_id'] : false,
                    ]
                ) ?>
            </span>
        </div>

        <!-- Comment (full width) -->
        <div class="w-100 mt-1">
            <?= $this->Form->textarea('Attribute.' . $k . '.comment', [
                'class'       => 'form-control form-control-sm ov-obj-row-comment',
                'placeholder' => __('Comment (optional)'),
                'rows'        => 1,
                'required'    => false,
                'allowEmpty'  => true,
                'value'       => empty($element['comment']) ? '' : $element['comment'],
                'label'       => false,
                'div'         => false,
            ]) ?>
        </div>

    </div>

</div>
