<?php
$edit = $this->request->params['action'] === 'edit';

echo $this->Form->create('GalaxyClusterRelation', [
    'class' => 'needs-validation',
    'novalidate' => true
]);
?>

<div class="container me-5">

    <div class="row justify-content-center">

        <div class="card shadow-sm">

            <div class="card-body">

                <h3 class="mb-2">
                    <?= $edit ? __('Edit Galaxy Cluster Relationship') : __('Add Galaxy Cluster Relationship') ?>
                </h3>

                <div class="form-text mb-3">
                    <?= __('Relationships link two galaxy clusters together and explain the context of their connection.') ?>
                </div>

                <!-- SOURCE UUID -->
                <div class="mb-3">
                    <?= $this->Form->label('galaxy_cluster_uuid', __('Source UUID'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('galaxy_cluster_uuid', [
                        'class' => 'form-control font-monospace',
                        'required' => true,
                        'readonly' => $edit,
                        'placeholder' => __('UUID of the cluster the relationship originates from')
                    ]) ?>
                    <?php if ($edit): ?>
                        <div class="form-text"><?= __('The source cluster of an existing relationship cannot be changed.') ?></div>
                    <?php endif; ?>
                </div>

                <!-- TARGET UUID -->
                <div class="mb-3">
                    <?= $this->Form->label('referenced_galaxy_cluster_uuid', __('Target UUID'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('referenced_galaxy_cluster_uuid', [
                        'class' => 'form-control font-monospace',
                        'required' => true,
                        'placeholder' => __('UUID of the cluster the relationship points to')
                    ]) ?>
                </div>

                <!-- DISTRIBUTION -->
                <div class="mb-3">
                    <?= $this->Form->label('distribution', __('Distribution'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->select('distribution', $distributionLevels, [
                        'class' => 'form-select',
                        'empty' => false,
                        'default' => $initialDistribution
                    ]) ?>
                </div>

                <!-- SHARING GROUP (shown for distribution == 4 only) -->
                <div class="mb-3" id="sharingGroupField">
                    <?= $this->Form->label('sharing_group_id', __('Sharing Group'), ['class' => 'form-label fw-semibold']) ?>
                    <?php
                        // A zero-option select is rendered but never added to the
                        // SecurityComponent fields-hash, blackholing every submit —
                        // always provide at least one (empty) option.
                        $sgOptions = ['class' => 'form-select'];
                        if (empty($sharingGroups)) {
                            $sgOptions['empty'] = __('No sharing group available');
                        }
                        echo $this->Form->select('sharing_group_id', $sharingGroups, $sgOptions);
                    ?>
                </div>

                <!-- RELATIONSHIP TYPE -->
                <div class="mb-3">
                    <?= $this->Form->label('referenced_galaxy_cluster_type', __('Relationship Type'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->text('referenced_galaxy_cluster_type', [
                        'class' => 'form-control',
                        'required' => true,
                        'placeholder' => __('is-similar'),
                        'list' => 'existingRelationshipTypes'
                    ]) ?>
                    <datalist id="existingRelationshipTypes">
                        <?php foreach ($existingRelations as $relationshipType): ?>
                            <option value="<?= h($relationshipType) ?>"></option>
                        <?php endforeach; ?>
                    </datalist>
                    <div class="form-text"><?= __('Free text — pick one of the known types from the suggestions or define your own.') ?></div>
                </div>

                <!-- TAGS -->
                <div class="mb-4">
                    <?= $this->Form->label('tags', __('Tag list'), ['class' => 'form-label fw-semibold']) ?>
                    <?= $this->Form->textarea('tags', [
                        'class' => 'form-control font-monospace',
                        'rows' => 3,
                        'placeholder' => 'estimative-language:likelihood-probability="very-likely", false-positive:risk="low"'
                    ]) ?>
                    <div class="form-text"><?= __('Comma separated list of tag names to attach to the relationship.') ?></div>
                </div>

                <!-- ACTIONS -->
                <div class="d-flex justify-content-end gap-3">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                        <?= __('Cancel') ?>
                    </button>
                    <?= $this->Form->button(
                        '<i class="fas fa-check me-1"></i> ' . ($edit ? __('Save changes') : __('Add relationship')),
                        [
                            'class' => 'btn btn-primary',
                            'escapeTitle' => false,
                            'title' => $edit ? __('Save changes') : __('Add relationship'),
                            'aria-label' => $edit ? __('Save changes') : __('Add relationship'),
                        ]
                    ) ?>
                </div>

            </div>

        </div>

    </div>

</div>

<?= $this->Form->end(); ?>

<script>
    // Show the sharing-group picker only when distribution is set to 4
    // (legacy checkSharingGroup() lives in misp.js, which is not loaded
    // under Overmind — openModal() re-executes this inline script).
    (function () {
        var distribution = document.getElementById('GalaxyClusterRelationDistribution');
        var sharingGroupField = document.getElementById('sharingGroupField');
        if (!distribution || !sharingGroupField) {
            return;
        }
        function toggleSharingGroup() {
            sharingGroupField.style.display = distribution.value === '4' ? '' : 'none';
        }
        distribution.addEventListener('change', toggleSharingGroup);
        toggleSharingGroup();
    })();
</script>
