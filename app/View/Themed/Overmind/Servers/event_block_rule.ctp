<?= $this->Form->create('Server', [
    'url' => $baseurl . '/servers/eventBlockRule',
    'id' => 'eventBlockRuleForm',
    'novalidate' => true,
]) ?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Blocklisting'),
    'title' => __('Event Block Rules'),
    'description' => __('A new event carrying any of these tags is refused, whether it is created here or received through synchronisation. Events already on this instance are left alone.'),
    'titleIcon' => 'fas fa-filter-circle-xmark',
    'icon' => 'fas fa-ban',
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'value',
                'label' => __('Rule set'),
                'shape' => 'object',
                'value' => $setting['AdminSetting']['value'] ?? '',
                'rows' => 10,
                'placeholder' => "{\n    \"tags\": [\"tlp:red\", \"pandemic:covid-19=\\\"cyber\\\"\"]\n}",
                'emptyLabel' => __('No rule'),
                'hint' => __('Exact tag names under "tags", one or a list; an event matching any of them is blocked. There is no NOT or AND. Leave the box empty to block nothing.'),
            ]) ?>
        </div>
    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'align' => 'end',
        'cancel' => false,
        'submit' => ['label' => __('Save'), 'icon' => 'fas fa-floppy-disk'],
    ]) ?>

</div>

<?= $this->Form->end() ?>
