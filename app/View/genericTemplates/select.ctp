<div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
            <span aria-hidden="true">&times;</span>
        </button>
        <h3 id="genericModalLabel"><?= h($title) ?></h3>
    </div>
    <?= $this->Form->create($model, ['onsubmit' => $onsubmit ?? null, 'style' => 'margin:0']) ?>
    <div class="modal-body modal-body-long">
        <p><?= h($description) ?></p>
        <?php
        echo $this->Form->input('relationship_type', [
            'type' => 'select',
            'options' => $options,
            'default' => $default ?? null,
        ]);
        echo $this->Form->input('relationship_type_custom', array(
            'label' => __('Custom Relationship Type'),
            'default' => $default_custom ?? null,
        ));
        ?>
    </div>
    <div class="modal-footer">
        <button type="submit" class="btn btn-primary"><?= __('Submit') ?></button>
        <button type="button" class="btn btn-secondary cancel-button" data-dismiss="modal"><?= __('Cancel') ?></button>
    </div>
    <?= $this->Form->end() ?>
</div>

<script>
    $(document).ready(function() {
        function toggleCustomType() {
            if ($('#TagRelationshipType').val() == 'custom') {
                $('#TagRelationshipTypeCustom').parent().show()
            } else {
                $('#TagRelationshipTypeCustom').parent().hide()
            }
        }

        toggleCustomType()
        $('#TagRelationshipType').change(toggleCustomType)

    })
</script>