<?php

$seed = 's-' . mt_rand();
$fieldData['type']  = 'select';
if (empty($fieldData['class'])) {
    $fieldData['class'] = $seed;
} else {
    $fieldData['class'] .= ' ' . $seed;
}

echo $this->Form->input($fieldData['field'], $fieldData);
if (!empty($params['description'])) {
    echo sprintf('<small class="clear form-field-description apply_css_arrow">%s</small>', h($params['description']));
}
?>

<?php if (!empty($fieldData['picker'])) : ?>
    <script>
        var chosenOptions = <?= JsonTool::encode($fieldData['_chosenOptions'] ?? []) ?>;
        $('select.<?= $seed ?>').chosen(chosenOptions)
    </script>
<?php endif; ?>
