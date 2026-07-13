<?php
$edit = $this->request->params['action'] === 'admin_edit';
$orgData = $this->request->data['Organisation'] ?? [];
$svgAllowed = (bool)Configure::read('Security.enable_svg_logos');

echo $this->Form->create('Organisation', [
    'type' => 'file',
    'class' => 'needs-validation',
    'novalidate' => true,
]);
?>

<div class="container me-5">
    <div class="row justify-content-center">
        <div class="card shadow-sm">
            <div class="card-body">

                <h3 class="mb-3">
                    <?= $edit ? __('Edit Organisation') : __('Add Organisation') ?>
                </h3>

                <!-- LOCAL ORGANISATION -->
                <div class="form-check form-switch mb-2">
                    <?= $this->Form->checkbox('local', [
                        'class' => 'form-check-input',
                        'id' => 'OrganisationLocal',
                        'checked' => $edit ? !empty($orgData['local']) : true,
                    ]) ?>
                    <?= $this->Form->label('OrganisationLocal', __('Local organisation'), ['class' => 'form-check-label']) ?>
                </div>
                <div class="form-text mb-3">
                    <?= __('If the organisation should have access to this instance, make sure that the Local organisation setting is checked. If you would only like to add a known external organisation for inclusion in sharing groups, uncheck the Local organisation setting.') ?>
                </div>

                <div class="fw-semibold mb-2"><?= __('Mandatory fields') ?></div>
                <div class="row">
                    <!-- NAME -->
                    <div class="col-md-6 mb-3">
                        <?= $this->Form->label('name', __('Organisation Identifier'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->text('name', [
                            'class' => 'form-control',
                            'placeholder' => __('Brief organisation identifier'),
                            'required' => true,
                        ]) ?>
                    </div>

                    <!-- UUID -->
                    <div class="col-md-6 mb-3">
                        <?= $this->Form->label('uuid', __('UUID'), ['class' => 'form-label fw-semibold']) ?>
                        <div class="input-group">
                            <?= $this->Form->text('uuid', [
                                'class' => 'form-control',
                                'id' => 'OrganisationUuid',
                                'placeholder' => __('Paste UUID or click generate'),
                            ]) ?>
                            <button type="button" class="btn btn-outline-secondary" onclick="generateOrgUUID();"
                                title="<?= h(__('Generate a new UUID for the organisation')) ?>">
                                <?= __('Generate UUID') ?>
                            </button>
                        </div>
                    </div>
                </div>

                <div class="fw-semibold mb-2 mt-2"><?= __('Optional fields') ?></div>

                <!-- DESCRIPTION -->
                <div class="mb-3">
                    <?= $this->Form->label('description', __('A brief description of the organisation'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('description', [
                        'class' => 'form-control',
                        'rows' => 2,
                        'placeholder' => __('A description of the organisation that is purely informational.'),
                    ]) ?>
                </div>

                <!-- RESTRICTED TO DOMAIN -->
                <div class="mb-3">
                    <?= $this->Form->label('restricted_to_domain', __('Bind user accounts to domains (line separated)'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('restricted_to_domain', [
                        'class' => 'form-control',
                        'rows' => 2,
                        'placeholder' => __('Enter a (list of) domain name(s) to enforce when creating users.'),
                    ]) ?>
                </div>

                <!-- LOGO -->
                <div class="mb-3">
                    <?= $this->Form->label('logo', __('Logo (48×48 %s)', $svgAllowed ? 'PNG or SVG' : 'PNG'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->file('logo', ['class' => 'form-control']) ?>
                </div>

                <div class="row">
                    <!-- NATIONALITY -->
                    <div class="col-md-4 mb-3">
                        <?= $this->Form->label('nationality', __('Nationality'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->select('nationality', $countries, [
                            'class' => 'form-select',
                            'empty' => false,
                        ]) ?>
                    </div>

                    <!-- SECTOR -->
                    <div class="col-md-4 mb-3">
                        <?= $this->Form->label('sector', __('Sector'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->text('sector', [
                            'class' => 'form-control',
                            'placeholder' => __('For example "financial".'),
                        ]) ?>
                    </div>

                    <!-- TYPE -->
                    <div class="col-md-4 mb-3">
                        <?= $this->Form->label('type', __('Type of organisation'), ['class' => 'form-label fw-semibold']) ?>
                        <?= $this->Form->text('type', [
                            'class' => 'form-control',
                            'placeholder' => __('Freetext description of the org.'),
                        ]) ?>
                    </div>
                </div>

                <!-- CONTACTS -->
                <div class="mb-4">
                    <?= $this->Form->label('contacts', __('Contact details'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('contacts', [
                        'class' => 'form-control',
                        'rows' => 2,
                        'placeholder' => __('You can add some contact details for the organisation here, if applicable.'),
                    ]) ?>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3 mt-4">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Edit') : __('Add')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Edit') : __('Add'),
                            'aria-label' => $edit ? __('Edit') : __('Add'),
                        ]
                    ) ?>
                </div>

            </div>
        </div>
    </div>
</div>

<?= $this->Form->end(); ?>
