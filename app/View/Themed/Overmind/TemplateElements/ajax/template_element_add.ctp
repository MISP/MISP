<?php
$edit = $this->request->params['action'] === 'editV2' ? true : false;

$currentType = isset($this->request->data['TemplateElementData']['element_definition']) 
    ? $this->request->data['TemplateElementData']['element_definition'] 
    : null;

echo $this->Form->create('TemplateElementData', [
    'url' => $baseurl . '/templateElements/' . ($edit ? 'editV2/' : 'addV2/') . $id,
    'class' => 'needs-validation',
    'id' => 'templateElementAddForm',
    'novalidate' => true
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-3">
                    <?= $edit ? __('Edit Element') : __('Add Element To Template') ?>
                </h3>

                <div id="formWarning" class="alert alert-danger d-none ajaxMessage"></div>

                <!-- ELEMENT DEFINITION -->
                <div class="mb-4">
                    <?= $this->Form->label('element_definition', __('Element Type'), ['class' => 'form-label fw-semibold text-primary']) ?>
                    <?= $this->Form->select('element_definition', [
                        'attribute' => __('Attribute'),
                        'file' => __('File'),
                        'text' => __('Text')
                    ], [
                        'class' => 'form-select tom-select bg-light border-primary',
                        'data-placeholder' => __('Choose the element type to add...'),
                        'id' => 'ElementTypeSelector',
                        'required' => true,
                        'disabled' => $edit,
                        'default' => $currentType
                    ]) ?>

                    <?php if ($edit): ?>
                        <?= $this->Form->hidden('element_definition', ['value' => $currentType]) ?>
                    <?php endif; ?>
                </div>

                <div id="dynamicFormFields" class="d-none">
                    <hr class="mb-4">

                    <!-- NAME -->
                    <div class="mb-3">
                        <?= $this->Form->label('name', __('Name'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->control('name', [
                            'label' => false,
                            'class' => 'form-control bg-light',
                            'required' => true
                        ]) ?>
                    </div>

                    <!-- DESCRIPTION -->
                    <div class="mb-4">
                        <?= $this->Form->label('description', __('Description / Text content'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->textarea('description', [
                            'class' => 'form-control bg-light',
                            'rows' => 4
                        ]) ?>
                    </div>

                    <!-- CATEGORY -->
                    <div class="mb-3 element-group-attr element-group-file d-none">
                        <?= $this->Form->label('category', __('Category'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->select('category', ['' => ''], [
                            'id' => 'DynamicCategory',
                            'class' => 'form-select tom-select bg-light',
                            'data-placeholder' => __('Select Category...')
                        ]) ?>
                    </div>

                    <!-- TYPE -->
                    <div class="mb-4 element-group-attr d-none">
                        <?= $this->Form->label('type', __('Type'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->select('type', ['' => ''], [
                            'id' => 'DynamicType',
                            'class' => 'form-select tom-select bg-light',
                            'data-placeholder' => __('Select Type...')
                        ]) ?>
                    </div>

                    <!-- OPTIONS -->
                    <div class="mb-4">
                        <div class="form-check form-switch mb-2 element-group-attr d-none" title="<?= __('Some categories can use complex types...') ?>">
                            <?= $this->Form->checkbox('complex', ['class' => 'form-check-input', 'id' => 'checkComplex']) ?>
                            <?= $this->Form->label('checkComplex', __('Use complex types'), ['class' => 'form-check-label']) ?>
                        </div>
                        <div class="form-check form-switch mb-2 element-group-attr d-none">
                            <?= $this->Form->checkbox('to_ids', ['class' => 'form-check-input', 'id' => 'checkIds']) ?>
                            <?= $this->Form->label('checkIds', __('Automatically mark for IDS'), ['class' => 'form-check-label']) ?>
                        </div>
                        <div class="form-check form-switch mb-2 element-group-file d-none">
                            <?= $this->Form->checkbox('malware', ['class' => 'form-check-input', 'id' => 'checkMalware']) ?>
                            <?= $this->Form->label('checkMalware', __('Malware'), ['class' => 'form-check-label']) ?>
                        </div>
                        <div class="form-check form-switch mb-2 element-group-attr element-group-file d-none">
                            <?= $this->Form->checkbox('mandatory', ['class' => 'form-check-input', 'id' => 'checkMandatory']) ?>
                            <?= $this->Form->label('checkMandatory', __('Mandatory element'), ['class' => 'form-check-label']) ?>
                        </div>
                        <div class="form-check form-switch mb-2 element-group-attr element-group-file d-none">
                            <?= $this->Form->checkbox('batch', ['class' => 'form-check-input', 'id' => 'checkBatch']) ?>
                            <?= $this->Form->label('checkBatch', __('Batch import element'), ['class' => 'form-check-label']) ?>
                        </div>
                    </div>

                     <!-- ACTION -->
                    <div class="d-flex justify-content-end gap-3">
                        <button type="button"
                                class="btn btn-outline-secondary"
                                data-bs-dismiss="modal">
                            <?= __('Cancel') ?>
                        </button>
                        <?= $this->Form->button(
                            '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit element') : __('Add new element')), 
                            [
                                'class' => 'btn btn-primary',
                                'escapeTitle' => false,
                                'title' => $edit ? __('Edit element') : __('Add new element'),
                                'aria-label' => $edit ? __('Edit element') : __('Add new element'),
                            ]
                        ) ?>
                    </div>
                </div>

            </div>
        </div>
    </div>
</div>

<?= $this->Form->end(); ?>


<script type="application/json" id="templateElementFormConfig">
<?= json_encode([
    'categoriesAttr' => $categoriesAttr ?? [],
    'categoriesFile' => $categoriesFile ?? [],
    'categoryTypesAttr' => isset($categoryDefinitionsAttr) ? array_map(function($c){ return $c['types']; }, $categoryDefinitionsAttr) : [],
    'typeGroupCategoryMapping' => $typeGroupCategoryMapping ?? [],
    'preSelectedCategory' => $this->request->data['TemplateElementData']['category'] ?? '',
    'preSelectedType' => $this->request->data['TemplateElementData']['type'] ?? ''
], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>
</script>