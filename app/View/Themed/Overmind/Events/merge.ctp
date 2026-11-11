<?php

$uid = 'evt-merge-' . dechex(mt_rand());
$targetId = $target_event['Event']['id'];

echo $this->Form->create('Event', [
    'id' => 'PromptForm',
    'url' => $baseurl . '/events/merge/' . $targetId,
    'class' => 'm-0',
]);
?>
<div style="border-radius: var(--bs-modal-border-radius, var(--bs-border-radius-lg)); overflow: hidden;">
    <?= $this->element('genericElementsBS5/Forms/modal_header', [
        'accent' => 'event',
        'eyebrow' => __('Event'),
        'title' => __('Merge attributes from'),
        'description' => __('Copies the attributes, objects and reports of another event into this one.'),
        'titleIcon' => 'fas fa-layer-group',
        'icon' => 'fas fa-layer-group',
    ]) ?>

    <div class="px-4 py-4 d-flex flex-column gap-3">
        <div>
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'event',
                'label' => __('Source event'),
                'required' => true,
                'for' => $uid . '-source',
            ]) ?>
            <?= $this->Form->text('source_id', [
                'class' => 'form-control',
                'id' => $uid . '-source',
                'placeholder' => __('ID or UUID of the event to merge from'),
                'autocomplete' => 'off',
            ]) ?>
            <div id="<?= h($uid) ?>-preview"></div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Nothing is written yet: the next screen lists what would be copied and lets you choose.'),
            ]) ?>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'event',
        'bleed' => true,
        'meta' => [['label' => __('Into event'), 'id' => $targetId]],
        'cancel' => ['label' => __('Cancel'), 'icon' => 'fas fa-xmark'],
        'submit' => [
            'label' => __('Review merge'),
            'icon' => 'fas fa-layer-group',
            'type' => 'submit',
            'id' => $uid . '-submit',
            // merge() throws on an empty source_id
            'disabled' => true,
        ],
    ]) ?>
</div>
<?= $this->Form->end() ?>

<script>
(function () {
    var input = document.getElementById('<?= $uid ?>-source');
    var preview = document.getElementById('<?= $uid ?>-preview');
    var submit = document.getElementById('<?= $uid ?>-submit');
    if (!input || !preview) {
        return;
    }

    var timer = null;
    var lastAsked = null;

    function render(value) {
        if (value === '') {
            preview.innerHTML = '';
            return;
        }
        lastAsked = value;
        fetch('<?= h($baseurl) ?>/events/getEventInfoById/' + encodeURIComponent(value),
              { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (response) { return response.ok ? response.text() : ''; })
            .then(function (html) {
                // a slower answer for an older value must not overwrite a newer one
                if (lastAsked === value) {
                    preview.innerHTML = html;
                }
            })
            .catch(function () { preview.innerHTML = ''; });
    }

    input.addEventListener('input', function () {
        var value = input.value.trim();
        if (submit) {
            submit.disabled = value === '';
        }
        window.clearTimeout(timer);
        timer = window.setTimeout(function () { render(value); }, 250);
    });
})();
</script>
