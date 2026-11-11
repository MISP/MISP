<?php
$isFalsePositive = (int)$sighting_type === 1;
$typeLabel = $isFalsePositive ? __('false positive') : __('sighting');

echo $this->Form->create('Sighting', [
    'id' => 'PromptForm',
    'url' => $baseurl . '/sightings/add/' . h($id),
]);
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'sighting',
        'eyebrow' => __('Sightings'),
        'title' => $isFalsePositive ? __('Mark value as false positive') : __('Add sighting on value'),
        'description' => __('Applies to every attribute you can see that holds this value.'),
        'titleIcon' => $isFalsePositive ? 'far fa-thumbs-down' : 'far fa-thumbs-up',
        'icon' => 'misp-icon misp-icon-sighting misp-simple',
    ]) ?>

    <div class="px-4 py-4">
        <?= $this->element('genericElementsBS5/Forms/section_label', [
            'accent' => 'sighting',
            'label' => __('Value'),
        ]) ?>
        <code class="d-block p-2 rounded bg-body-tertiary text-break"><?= h($tosight) ?></code>
        <?= $this->element('genericElementsBS5/Forms/field_hint', [
            'text' => __('One %s will be recorded for your organisation on each match.', $typeLabel),
        ]) ?>
        <?= $this->Form->text('value', ['value' => $value, 'class' => 'd-none']) ?>
        <?= $this->Form->text('type', ['value' => (int)$sighting_type, 'class' => 'd-none']) ?>

        <?= $this->element('genericElementsBS5/Forms/modal_footer', [
            'accent' => 'sighting',
            'cancel' => ['label' => __('Cancel')],
            'submit' => [
                'label' => $isFalsePositive ? __('Mark as false positive') : __('Add sighting'),
                'icon' => $isFalsePositive ? 'far fa-thumbs-down' : 'far fa-thumbs-up',
                'type' => 'submit',
            ],
        ]) ?>
    </div>
</div>
<?= $this->Form->end() ?>
