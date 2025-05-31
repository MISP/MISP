<div id="genericModal" class="modal hide fade" tabindex="-1" role="dialog" aria-labelledby="genericModalLabel" aria-hidden="true">
    <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-hidden="true">
            <span aria-hidden="true">&times;</span>
        </button>
        <h3 id="genericModalLabel"><?= h($title) ?></h3>
    </div>
    <?= $this->Form->create($model, ['onsubmit' => $onsubmit ?? null, 'style' => 'margin:0']) ?>
    <div class="modal-body modal-body-long" style="min-height: 400px;">
        <p><?= h($description) ?></p>
        <?php
        $pickerOptions = [
            'flag_redraw_chosen' => true,
            'disabledSubmitButton' => true,
            'functionName' => 'mirrorChange',
        ];
        $items = [];
        foreach ($options as $option) {
            $displayName = $option['name'];
            if (!empty($option['highlighted'])) {
                $displayName = '★ ' . $option['name'];
            }
            $value = array_key_exists('value', $option) ? $option['value'] : $option['name'];
            $items[] = [
                'selected' => $value == $default ?? null,
                'name' => $displayName,
                'value' => $value,
                'template' => [
                    'name' => $displayName,
                    'infoExtra' => $option['description'],
                ]
            ];
        }
        $textOptions = Hash::combine($items, '{n}.value', '{n}.name');
        echo $this->Form->input('relationship_type', [
            'type' => 'select',
            'options' => $textOptions,
            'default' => $default ?? null,
            'div' => 'hidden',
        ]);
        echo $this->element('generic_picker', ['items' => $items, 'options' => $pickerOptions]);
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

    function mirrorChange(value) {
        $('#TagRelationshipType').val(value).trigger('change')
    }
</script>