<?php
$isEdit = $this->request->params['action'] === 'edit';
$bookmark = $this->request->data['Bookmark'] ?? [];

echo $this->Form->create('Bookmark', [
    'id' => 'bookmarkForm',
    'novalidate' => true,
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Bookmarks'),
    'title' => $isEdit ? __('Edit Bookmark') : __('Add Bookmark'),
    'description' => __('Bookmarks sit in the navigation top bar. One can optionally be exposed to every user of your organisation.'),
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
                'style' => 'border-bottom:1px solid #d8dde3 !important; outline:none;',
                'placeholder' => __('e.g. My org\'s open events'),
                'autocomplete' => 'off',
                'required' => true,
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('This is the label shown in the top bar.'),
            ]) ?>
        </div>

        <!-- ── TARGET ──────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('URL'),
                'required' => true,
            ]) ?>
            <div class="input-group">
                <span class="input-group-text bg-transparent"
                      style="border-color:#d8dde3;">
                    <i class="fas fa-link text-muted" style="font-size:.8rem;"></i>
                </span>
                <?= $this->Form->textarea('url', [
                    'id' => 'BookmarkUrl',
                    'class' => 'form-control font-monospace',
                    'style' => 'border-color:#d8dde3; resize:vertical;',
                    'rows' => 2,
                    'spellcheck' => 'false',
                    'placeholder' => '/events/index/searchpublished:0',
                    'required' => true,
                ]) ?>
            </div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('An instance-relative path or a full URL.'),
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
                'style' => 'border-color:#d8dde3;',
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
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Left off, the bookmark stays in your own top bar.'),
            ]) ?>
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
