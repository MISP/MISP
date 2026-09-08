<?php
/*
 * event_delegations/delegateEvent — ask another organisation to take ownership
 * of this event.
 *
 * Every field goes through FormHelper: the SecurityComponent hash covers the
 * fields FormHelper saw, and delegateEvent() reads them back as
 * data[EventDelegation][…].
 *
 * Set by the controller:
 *   $org                 array  id => name of the candidate organisations
 *   $distributionOptions array  '-1' => 'Recipient decides' + the levels
 *   $sgOptions           array  id => name of the authorised sharing groups
 *   $id                  int    event id
 */

$uid = 'evt-delegate-' . dechex(mt_rand());

$sharingGroupLevel = '4';

echo $this->Form->create('EventDelegation', [
    'id' => 'PromptForm',
    'url' => $this->request->here(false),
    'class' => 'm-0',
]);
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'warning',
        'eyebrow' => __('Publication'),
        'title' => __('Delegate publishing'),
        'description' => __('Asks another organisation to take ownership of this event and publish it.'),
        'titleIcon' => 'fas fa-handshake',
        'icon' => 'fas fa-handshake',
    ]) ?>

    <div class="px-4 py-4 d-flex flex-column gap-3">
        <div class="d-flex gap-2 p-3 rounded-2 bg-warning-subtle text-warning-emphasis border-start border-3 border-warning"
             role="note">
            <i class="fas fa-triangle-exclamation" style="font-size:.8rem; margin-top:.15rem;"></i>
            <div class="lh-base" style="font-size:.8rem;">
                <?= __('Once the request is accepted, the recipient organisation becomes the owner of this event and yours is no longer credited as the creator.') ?>
            </div>
        </div>

        <div>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'warning',
                'label' => __('Target organisation'),
                'required' => true,
                'for' => $uid . '-org',
            ]) ?>
            <?= $this->Form->select('org_id', $org, [
                'class' => 'form-select',
                'id' => $uid . '-org',
                'empty' => __('Select organisation'),
            ]) ?>
        </div>

        <div>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'warning',
                'label' => __('Desired distribution'),
                'for' => $uid . '-distribution',
            ]) ?>
            <?= $this->Form->select('distribution', $distributionOptions, [
                'class' => 'form-select',
                'id' => $uid . '-distribution',
                'empty' => false,
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('"Recipient decides" leaves the choice to the organisation taking over.'),
            ]) ?>
        </div>

        <div id="<?= h($uid) ?>-sg-wrapper" class="d-none">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'warning',
                'label' => __('Desired sharing group'),
                'for' => $uid . '-sg',
            ]) ?>
            <?= $this->Form->select('sharing_group_id', $sgOptions, [
                'class' => 'form-select',
                'id' => $uid . '-sg',
                'empty' => false,
            ]) ?>
        </div>

        <div>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'warning',
                'label' => __('Message'),
                'for' => $uid . '-message',
            ]) ?>
            <?= $this->Form->textarea('message', [
                'class' => 'form-control',
                'id' => $uid . '-message',
                'rows' => 3,
                'placeholder' => __('Message to the recipient organisation'),
            ]) ?>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'warning',
        'bleed' => true,
        'meta' => [['label' => __('Event'), 'id' => $id]],
        'cancel' => ['label' => __('Cancel'), 'icon' => 'fas fa-xmark'],
        'submit' => [
            'label' => __('Request delegation'),
            'icon' => 'fas fa-handshake',
            'type' => 'submit',
        ],
    ]) ?>
</div>
<?= $this->Form->end() ?>

<script>
(function () {
    var level = document.getElementById('<?= $uid ?>-distribution');
    var wrapper = document.getElementById('<?= $uid ?>-sg-wrapper');
    if (!level || !wrapper) {
        return;
    }

    function sync() {
        wrapper.classList.toggle('d-none', level.value !== '<?= $sharingGroupLevel ?>');
    }
    level.addEventListener('change', sync);
    sync();
})();
</script>
