<?php
$isEdit = $this->request->params['action'] === 'edit';
$news = $this->request->data['News'] ?? [];

// No novalidate: the browser stops an empty field, which the server would
// otherwise answer with the bare form outside the modal.
echo $this->Form->create('News', [
    'id' => 'newsForm',
]);

echo $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('News'),
    'title' => $isEdit ? __('Edit news item') : __('Add news item'),
    'description' => __('News items are shown to every user in the News panel of the navbar, highlighted until they read them.'),
    'icon' => 'fas fa-newspaper',
    'isEdit' => $isEdit,
]);
?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── TITLE ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Title'),
                'required' => true,
                'for' => 'NewsTitle',
            ]) ?>
            <?= $this->Form->text('title', [
                'id' => 'NewsTitle',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid var(--misp-field-line, #d8dde3) !important; outline:none;',
                'placeholder' => __('e.g. Scheduled maintenance on Saturday'),
                'autocomplete' => 'off',
                'required' => true,
            ]) ?>
        </div>

        <!-- ── MESSAGE ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'label' => __('Message'),
                'required' => true,
                'for' => 'NewsMessage',
            ]) ?>
            <?= $this->Form->textarea('message', [
                'id' => 'NewsMessage',
                'class' => 'form-control',
                'style' => 'border-color:var(--misp-field-line, #d8dde3); resize:vertical;',
                'rows' => 8,
                'placeholder' => __('What users need to know'),
                'required' => true,
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'icon' => 'fab fa-markdown mt-1',
                'text' => __('Markdown is supported: emphasis, lists, links, code. Images are not shown.'),
            ]) ?>
        </div>

        <?php if (!$isEdit): ?>
            <!-- ── AUTHOR ──────────────────────────────────────── -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'label' => __('Author'),
                ]) ?>
                <div class="form-check form-switch">
                    <?= $this->Form->checkbox('anonymise', [
                        'class' => 'form-check-input',
                        'id' => 'NewsAnonymise',
                        'hiddenField' => true,
                    ]) ?>
                    <?= $this->Form->label('NewsAnonymise', __('Post anonymously'), ['class' => 'form-check-label']) ?>
                </div>
            </div>
        <?php endif; ?>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($news['id'])
            ? [['label' => __('News item'), 'id' => $news['id']]]
            : [],
        'hint' => $isEdit ? '' : __('Every user sees it as new until they open the News panel.'),
        'submit' => $isEdit
            ? ['label' => __('Save Changes')]
            : ['label' => __('Publish'), 'icon' => 'fas fa-paper-plane'],
    ]) ?>

</div>

<?= $this->Form->end() ?>
