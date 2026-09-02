<?php

$uid = 'evt-contact-' . dechex(mt_rand());
$eventId = $event['Event']['id'];
$orgcName = $event['Orgc']['name'] ?? __('the reporting organisation');

echo $this->Form->create('Event', [
    'id' => 'PromptForm',
    'url' => $baseurl . '/events/contact/' . $eventId,
    'class' => 'm-0',
]);
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'primary',
        'eyebrow' => __('Event'),
        'title' => __('Contact reporter'),
        'description' => __('Emails %s about this event.', $orgcName),
        'titleIcon' => 'fas fa-envelope',
        'icon' => 'fas fa-envelope',
    ]) ?>

    <div class="px-4 py-4 d-flex flex-column gap-3">
        <div>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Message'),
                'for' => $uid . '-message',
            ]) ?>
            <?= $this->Form->textarea('message', [
                'class' => 'form-control',
                'id' => $uid . '-message',
                'rows' => 5,
                'placeholder' => __('What you would like to ask or tell them'),
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Your email address and the details of the event are appended automatically.'),
            ]) ?>
        </div>

        <div class="border rounded-2 px-3 py-3">
            <div class="form-check mb-0">
                <?= $this->Form->checkbox('person', [
                    'class' => 'form-check-input',
                    'id' => $uid . '-person',
                ]) ?>
                <label class="form-check-label fw-semibold" style="font-size:.85rem;"
                       for="<?= h($uid) ?>-person">
                    <?= __('Only the person who created the event') ?>
                </label>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Left off, every user of the reporting organisation who asked to be contacted receives it.'),
                'class' => 'mt-2',
            ]) ?>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'primary',
        'bleed' => true,
        'meta' => [['label' => __('Event'), 'id' => $eventId]],
        'cancel' => ['label' => __('Cancel'), 'icon' => 'fas fa-xmark'],
        'submit' => [
            'label' => __('Send'),
            'icon' => 'fas fa-paper-plane',
            'type' => 'submit',
        ],
    ]) ?>
</div>
<?= $this->Form->end() ?>
