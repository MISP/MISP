<?php
$seed = mt_rand();
$input = $this->Form->input($fieldData['field'], [
    'class' => ($fieldData['class'] ?? '') . ' tag-textarea',
    'label' => $fieldData['label'] ?? __('Tag list'),
    'type' => 'textarea',
    'placeholder' => $fieldData['placeholder'] ?? 'tlp:red, PAP:GREEN',
    'div' => 'input text input-append',
    'after' => sprintf('<button type="button" class="btn" onclick="pickerTags.call(this);">%s</button>', __('Pick tags')),
]);
?>

<div class="seed-<?= $seed ?>">
    <?= $input ?>
</div>

<script>
    function pickerTags() {
        $(this).data('popover-no-submit', true);
        $(this).data('popover-callback-function', setTagsAfterSelect);
        var target_id = 0;
        var target_type = 'galaxyClusterRelation';
        popoverPopup(this, target_id + '/' + target_type, 'tags', 'selectTaxonomy')
    }

    function setTagsAfterSelect(selected, additionalData) {
        selectedTags = [];
        selected.forEach(function(selection) {
            selectedTags.push(additionalData.itemOptions[selection].tag_name);
        });
        $('div.seed-<?= $seed ?> textarea.tag-textarea').val(JSON.stringify(selectedTags));
    }
</script>