<?php
$isEdit = $this->request->params['action'] === 'edit';
$bookmark = $this->request->data['Bookmark'] ?? [];

// No novalidate: the browser stops an empty name or an address without its
// protocol, which the server would otherwise answer with the bare form.
echo $this->Form->create('Bookmark', [
    'id' => 'bookmarkForm',
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Bookmarks'),
    'title' => $isEdit ? __('Edit Bookmark') : __('Add Bookmark'),
    'description' => __('Bookmarks sit in the Bookmarks panel of the navbar. One can optionally be exposed to every user of your organisation.'),
    'icon' => 'fas fa-bookmark',
    'isEdit' => $isEdit,
]);
?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Name'),
                'required' => true,
            ]) ?>
            <?= $this->Form->text('name', [
                'id' => 'BookmarkName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid var(--misp-field-line, #d8dde3) !important; outline:none;',
                'placeholder' => __('e.g. My org\'s open events'),
                'autocomplete' => 'off',
                'required' => true,
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('This is the label shown in the Bookmarks panel.'),
            ]) ?>
        </div>

        <!-- ── TARGET ──────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('URL'),
                'required' => true,
                'for' => 'BookmarkUrl',
            ]) ?>
            <div class="d-flex align-items-center gap-2"
                 style="border-bottom:1px solid var(--misp-field-line, #d8dde3);">
                <i class="fas fa-link text-muted" style="font-size:.85rem;" aria-hidden="true"></i>
                <?= $this->Form->text('url', [
                    'id' => 'BookmarkUrl',
                    'type' => 'url',
                    'class' => 'flex-grow-1 border-0 bg-transparent font-monospace py-1',
                    'style' => 'outline:none; min-width:0; font-size:1rem;',
                    'placeholder' => $baseurl . '/events/index/searchpublished:0',
                    'pattern' => 'https?://.+',
                    'title' => __('A full address, starting with http:// or https://'),
                    'spellcheck' => 'false',
                    'autocomplete' => 'off',
                    'required' => true,
                ]) ?>
            </div>
            <div id="BookmarkUrlTarget" class="align-items-center gap-2 mt-2 px-2 py-1 border rounded-pill small"
                 data-local="<?= h(__('This instance')) ?>" data-external="<?= h(__('Another site, opens in a new tab')) ?>"
                 style="display:none; max-width:100%;">
                <i aria-hidden="true"></i>
                <span class="fw-semibold" data-target-where></span>
                <span class="font-monospace text-muted text-truncate" data-target-path></span>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('A full address, starting with http:// or https://. Copy it from the address bar of the page to keep.'),
            ]) ?>
        </div>

        <!-- ── COMMENT ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Comment'),
            ]) ?>
            <?= $this->Form->textarea('comment', [
                'id' => 'BookmarkComment',
                'class' => 'form-control',
                'style' => 'border-color:var(--misp-field-line, #d8dde3);',
                'rows' => 3,
                'placeholder' => __('What this bookmark is for'),
            ]) ?>
        </div>

        <!-- ── VISIBILITY ──────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Visibility'),
            ]) ?>
            <div class="form-check form-switch">
                <?= $this->Form->checkbox('exposed_to_org', [
                    'class' => 'form-check-input',
                    'id' => 'BookmarkExposedToOrg',
                    'hiddenField' => true,
                ]) ?>
                <?= $this->Form->label(
                    'BookmarkExposedToOrg',
                    __('Expose to every user of my organisation'),
                    ['class' => 'form-check-label']
                ) ?>
            </div>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($bookmark['id'])
            ? [['label' => __('Bookmark'), 'id' => $bookmark['id']]]
            : [],
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Bookmark')],
    ]) ?>

</div>

<?= $this->Form->end() ?>
<script>
    (function () {
        var input = document.getElementById('BookmarkUrl');
        var target = document.getElementById('BookmarkUrlTarget');
        if (!input || !target) return;
        // Where the bookmark leads, as the bookmarks panel will open it.
        function show() {
            var url = null;
            try { url = new URL(input.value.trim()); } catch (e) { /* not an address yet */ }
            if (!url || !/^https?:$/.test(url.protocol)) {
                target.style.display = 'none';
                return;
            }
            var local = url.origin === location.origin;
            target.style.display = 'inline-flex';
            target.classList.toggle('text-primary-emphasis', local);
            target.classList.toggle('bg-primary-subtle', local);
            target.classList.toggle('border-primary-subtle', local);
            target.querySelector('i').className = 'fas ' + (local ? 'fa-house' : 'fa-arrow-up-right-from-square');
            target.querySelector('[data-target-where]').textContent = target.getAttribute(local ? 'data-local' : 'data-external');
            target.querySelector('[data-target-path]').textContent = local ? url.pathname + url.search : url.host;
        }
        input.addEventListener('input', show);
        show();
    })();
</script>
