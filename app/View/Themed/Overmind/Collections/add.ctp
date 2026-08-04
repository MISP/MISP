<?php
$edit = $this->request->params['action'] === 'edit' ? true : false;

echo $this->Form->create('Collection', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?=  $edit ? __('Edit current collection') : __('Create New Collection')  ?>
                </h3>

                <p class="text-muted mb-4">
                    <?= __('Create collections to organise data shared by the community into buckets based on commonalities or as part of your research process. Collections are first class citizens and adhere to the same sharing rules as for example events do.') ?>
                </p>

                <!-- NAME -->
                <div class="mb-3">
                    <?= $this->Form->label('name', __('Collection Name'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->control('name', [
                        'label' => false,
                        'class' => 'form-control bg-light',
                        'placeholder' => 'e.g., APTX Phishing Campaign Assets',
                        'maxlength' => 60,
                        'required' => true
                    ]) ?>

                    <div class="form-text">
                        <?= __('Keep it short but descriptive. Max 60 characters.') ?>
                    </div>
                </div>

                <!-- TYPE -->
                <div class="mb-3">
                    <?= $this->Form->label('type', __('Collection Type'), ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->select('type', $dropdownData['types'] ?? [], [
                        'empty' => __('Select a type...'),
                        'class' => 'form-select tom-select bg-light'
                    ]) ?>
                </div>

                <!-- DISTRIBUTION + SG -->
                <div class="mb-3">
                    <div class="row g-2 align-items-end">

                        <!-- DISTRIBUTION -->
                        <div class="col-md-6">
                            <?= $this->Form->label('distribution', __('Distribution'), ['class' => 'form-label fw-semibold']) ?>

                            <?= $this->Form->select('distribution', $dropdownData['distributionLevels'] ?? [], [
                                'empty' => __('Select a distribution...'),
                                'class' => 'form-select tom-select bg-light',
                                'id' => 'distribution-select'
                            ]) ?>
                        </div>

                        <!-- SHARING GROUP -->
                        <div class="col-md-6 d-none" id="sg-container">

                            <?= $this->Form->label('sharing_group_id', __('Sharing Group'), ['class' => 'form-label fw-semibold']) ?>

                            <?= $this->Form->select('sharing_group_id', $dropdownData['sgs'] ?? [], [
                                'empty' => __('Select a sharing group...'),
                                'class' => 'form-select tom-select bg-light',
                                'id' => 'sharing-group-select'
                            ]) ?>

                        </div>

                    </div>
                </div>

                <!-- DESCRIPTION -->
                <div class="mb-4">
                    <?= $this->Form->label('description', __('Description') . ' (Optional)', ['class' => 'form-label fw-semibold']) ?>

                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control bg-light',
                        'rows' => 4,
                        'placeholder' => __('Briefly describe what this collection is for and what kind of assets it contains...')
                    ]) ?>
                </div>

                <!-- ACTION -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button"
                            class="btn btn-outline-secondary"
                            data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit collection') : __('Add new collection')), 
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit collection') : __('Add new collection'),
                            'aria-label' => $edit ? __('Edit collection') : __('Add new collection'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>