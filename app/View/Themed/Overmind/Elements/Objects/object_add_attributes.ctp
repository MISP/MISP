<?php
if (empty($enabledRows)) $enabledRows = [];
if (empty($action))      $action      = 'add';

$isRequired = !empty($template['ObjectTemplate']['requirements']['required'])
    && in_array(
        $element['object_relation'],
        $template['ObjectTemplate']['requirements']['required'],
        true
    );

$isSaved  = in_array($k, $enabledRows, true);
$idsOn    = !empty($element['to_ids']);
$corrOff  = !empty($element['disable_correlation']);
$corrDis  = in_array($element['type'], MispAttribute::NON_CORRELATING_TYPES, true);
$initDist = !empty($element['distribution'])
    ? (int)$element['distribution']
    : (int)$distributionData['initial'];
?>

<div id="row_<?= h($k) ?>"
     class="attribute_row card mb-2 shadow-sm"
     style="border-left:3px solid var(--bs-object);
            opacity:<?= $isSaved ? '1' : '.5' ?>;
            transition:opacity .15s;">

    <!-- ── HEADER ──────────────────────────────────────────── -->
    <div class="card-header d-flex align-items-start gap-2 py-2 px-3"
         style="background:rgba(82,73,72,.04);">

        <!-- Save -->
        <div class="form-check mt-1 mb-0 flex-shrink-0">
            <?= $this->Form->input('Attribute.' . $k . '.save', [
                'type'    => 'checkbox',
                'checked' => $isSaved,
                'label'   => false,
                'div'     => false,
                'id'      => 'Attribute' . $k . 'Save',
            ]) ?>
        </div>

        <!-- Hidden fields -->
        <?= $this->Form->input('Attribute.' . $k . '.object_relation', [
            'type' => 'hidden', 'value' => $element['object_relation'],
            'label' => false, 'div' => false,
        ]) ?>
        <?php if ($action === 'edit'): ?>
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
                <span class="fw-bold lh-1 text-uppercase"
                      style="font-size:.78rem; color:var(--bs-object);">
                    <?= h(Inflector::humanize($element['object_relation'])) ?>
                </span>
                <?php if ($isRequired): ?>
                    <i class="fas fa-asterisk text-danger"
                       title="<?= __('Required') ?>"
                       style="font-size:.5rem; vertical-align:super;"></i>
                <?php endif; ?>
                <span class="badge rounded-pill bg-secondary fw-normal"
                      style="font-size:.62rem;">
                    <?= h($element['type']) ?>
                </span>
            </div>
            <?php if (!empty($element['description'])): ?>
            <div class="text-muted lh-sm mt-1"
                 style="font-size:.7rem;">
                <?= h($element['description']) ?>
            </div>
            <?php endif; ?>
        </div>

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
    <div class="card-footer py-2 px-3 d-flex flex-wrap align-items-center gap-2"
         style="background:rgba(0,0,0,.015);">

        <!-- Category -->
        <?= $this->Form->select(
            'Attribute.' . $k . '.category',
            array_combine($element['categories'], $element['categories']),
            [
                'default' => $element['default_category'],
                'class'   => 'form-select form-select-sm flex-shrink-0',
                'style'   => 'width:auto; font-size:.75rem;',
            ]
        ) ?>

        <!-- IDS toggle -->
        <label class="d-inline-flex align-items-center gap-1 rounded px-2 py-1 mb-0 user-select-none"
               id="card-ids-<?= $k ?>"
               title="<?= __('Send to IDS') ?>"
               style="cursor:pointer; font-size:.72rem;
                      border:1px solid <?= $idsOn ? '#ffc107' : '#dee2e6' ?>;
                      background:<?= $idsOn ? 'rgba(255,193,7,.08)' : 'transparent' ?>;
                      transition:border-color .15s, background .15s;">
            <?= $this->Form->input('Attribute.' . $k . '.to_ids', [
                'type'    => 'checkbox',
                'checked' => $idsOn,
                'label'   => false,
                'div'     => false,
                'style'   => 'display:none;',
            ]) ?>
            <i class="fas fa-shield-halved"
               style="font-size:.75rem;
                      color:<?= $idsOn ? '#ffc107' : '#adb5bd' ?>;"></i>
            <span><?= __('IDS') ?></span>
        </label>

        <!-- Correlate toggle -->
        <label class="d-inline-flex align-items-center gap-1 rounded px-2 py-1 mb-0 user-select-none"
               id="card-corr-<?= $k ?>"
               title="<?= __('Enable correlation') ?>"
               style="cursor:pointer; font-size:.72rem;
                      border:1px solid <?= (!$corrOff && !$corrDis) ? '#198754' : '#dee2e6' ?>;
                      background:<?= (!$corrOff && !$corrDis) ? 'rgba(25,135,84,.08)' : 'transparent' ?>;
                      transition:border-color .15s, background .15s;
                      <?= $corrDis ? 'opacity:.4; pointer-events:none;' : '' ?>">
            <?= $this->Form->input('Attribute.' . $k . '.disable_correlation', [
                'type'     => 'checkbox',
                'checked'  => $corrOff,
                'disabled' => $corrDis,
                'label'    => false,
                'div'      => false,
                'style'    => 'display:none;',
            ]) ?>
            <i class="fas <?= ($corrOff || $corrDis) ? 'fa-link-slash' : 'fa-link' ?>"
               style="font-size:.75rem;
                      color:<?= (!$corrOff && !$corrDis) ? '#198754' : '#adb5bd' ?>;"></i>
            <span><?= __('Correlate') ?></span>
        </label>

        <!-- Distribution + SG (pushed right) -->
        <div class="ms-auto d-flex align-items-center gap-2 flex-wrap">
            <span class="text-muted" style="font-size:.65rem; white-space:nowrap;">
                <?= __('Distrib.') ?>
            </span>
            <?= $this->Form->select(
                'Attribute.' . $k . '.distribution',
                $distributionData['levels'],
                [
                    'class'   => 'form-select form-select-sm Attribute_distribution_select',
                    'default' => $initDist,
                    'style'   => 'width:auto; font-size:.75rem;',
                ]
            ) ?>
            <?= $this->Form->select(
                'Attribute.' . $k . '.sharing_group_id',
                $distributionData['sgs'],
                [
                    'class'  => 'form-select form-select-sm Attribute_sharing_group_id_select',
                    'default' => !empty($element['sharing_group_id'])
                        ? $element['sharing_group_id'] : false,
                    'style'  => 'display:none; width:auto; font-size:.75rem;',
                ]
            ) ?>
        </div>

        <!-- Comment (full width) -->
        <div class="w-100 mt-1">
            <?= $this->Form->textarea('Attribute.' . $k . '.comment', [
                'class'       => 'form-control form-control-sm',
                'placeholder' => __('Comment (optional)'),
                'rows'        => 1,
                'required'    => false,
                'allowEmpty'  => true,
                'value'       => empty($element['comment']) ? '' : $element['comment'],
                'style'       => 'font-size:.8rem; resize:vertical;',
                'label'       => false,
                'div'         => false,
            ]) ?>
        </div>

    </div>

</div>
