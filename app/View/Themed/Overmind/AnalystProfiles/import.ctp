<?php
/**
 * Somebody else's profile, as a copy of their judgement.
 *
 * Import is the sharing path and the second of the two ways in — the
 * other is a fork. A uuid that already exists locally is re-minted
 * rather than overwritten, and an import lands **disabled** when the
 * owner already holds an enabled profile: reviewing a profile before
 * adopting it should not change your own pages underneath you first.
 *
 * Drawn as a modal from the index, as a page when navigated to.
 *
 * @var bool $can_import_for_org
 * @var bool $holds_enabled
 */
$isModal = !empty($ajax);

if (!$isModal) {
    $this->set('headerTitle', __('Import a profile'));
    $this->set('headerBreadcrumb', array(
        array('label' => __('Analyst Profiles'),
            'url' => array('action' => 'index')),
        __('Import'),
    ));
    $this->set('headerDescription', __('One JSON document, exported from an'
        . ' instance that already scores something.'));
}

echo $this->Form->create('AnalystProfile', array(
    'url' => $this->Html->url(array('action' => 'import')),
    'class' => 'needs-validation',
    'novalidate' => true,
));
?>

<?php if ($isModal): ?>
<?= $this->element('genericElementsBS5/Forms/modal_header', array(
    'accent' => 'primary',
    'eyebrow' => __('Analyst Profiles'),
    'title' => __('Import a profile'),
    'description' => __('One JSON document, exported from an instance that'
        . ' already scores something.'),
    'titleIcon' => 'fas fa-file-import',
    'icon' => 'fas fa-sliders',
)) ?>
<?php endif; ?>

<div class="<?= $isModal ? 'p-4' : 'container-fluid px-4 py-3' ?>"
     <?= $isModal ? '' : 'style="max-width:52rem"' ?>>

    <div class="alert alert-<?= $holds_enabled ? 'info' : 'warning'
        ?> d-flex gap-2 mb-4" role="note">
        <i class="fas fa-<?= $holds_enabled ? 'toggle-off' : 'bolt'
            ?> mt-1"></i>
        <div>
            <?= $holds_enabled
                ? h(__('You already hold an enabled profile, so this one'
                    . ' arrives disabled. Simulate it, and enable it when'
                    . ' you have decided.'))
                : h(__('You hold no enabled profile, so this one arrives'
                    . ' enabled and becomes the one in force.')) ?>
        </div>
    </div>

    <div class="d-flex flex-column gap-4">

        <!-- ── DOCUMENT ────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/json_field', array(
                'field' => 'json',
                'id' => 'ap-import-json',
                'label' => __('The document'),
                'shape' => 'object',
                'required' => true,
                'rows' => 16,
                'minHeight' => '300px',
                'placeholder' => "{\n    \"name\": \"…\",\n"
                    . "    \"description\": \"…\",\n"
                    . "    \"parameters\": {\n"
                    . "        \"signals\": {},\n"
                    . "        \"thresholds\": {},\n"
                    . "        \"relevance\": {},\n"
                    . "        \"context\": {},\n"
                    . "        \"enrichment\": {}\n"
                    . "    }\n}",
                'hint' => __('An export carries name, description, uuid,'
                    . ' version and parameters. Only parameters is'
                    . ' required — without it there would be nothing to'
                    . ' score with.'),
            )) ?>
        </div>

        <?php if ($can_import_for_org): ?>
            <!-- ── SCOPE ───────────────────────────────────────── -->
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label',
                    array('label' => __('Scope'))) ?>
                <div class="form-check form-switch">
                    <?= $this->Form->checkbox('for_org', array(
                        'class' => 'form-check-input',
                        'id' => 'ap-import-for-org',
                        'hiddenField' => false,
                    )) ?>
                    <label class="form-check-label" for="ap-import-for-org">
                        <?= h(__('Import for my organisation')) ?>
                    </label>
                </div>
                <?= $this->element('genericElementsBS5/Forms/field_hint',
                    array('text' => __('An organisation profile applies to'
                        . ' every colleague who has not enabled one of'
                        . ' their own.'))) ?>
            </div>
        <?php endif; ?>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', array(
        'hint' => __('A uuid that already exists here is re-minted, never'
            . ' overwritten.'),
        'cancel' => $isModal ? array() : array(
            'label' => __('Cancel'),
            'href' => $this->Html->url(array('action' => 'index')),
            'attrs' => array(),
        ),
        'submit' => array(
            'label' => __('Import'),
            'icon' => 'fas fa-upload',
        ),
    )) ?>
</div>

<?= $this->Form->end() ?>
