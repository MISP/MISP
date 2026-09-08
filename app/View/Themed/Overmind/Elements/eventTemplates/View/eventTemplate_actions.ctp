<?php
$tpl = $data['EventTemplate'] ?? [];
$templateId = (int)($tpl['id'] ?? 0);
$isActive = (int)($tpl['active'] ?? 0) === 1;

$actions = [];

if ($this->Acl->canAccess('eventTemplates', 'add')) {
    $actions[] = [
        'url' => "$baseurl/event_templates/edit/$templateId",
        'onclick' => "event.preventDefault(); openModal('"
            . "$baseurl/event_templates/edit/$templateId', 'xl');",
        'icon' => 'fas fa-pen-to-square',
        'label' => __('Edit this template'),
    ];
}


if ($this->Acl->canAccess('eventTemplates', 'instantiate') && $isActive) {
    $actions[] = [
        'url' => "$baseurl/event_templates/instantiate/$templateId",
        'onclick' => "event.preventDefault(); openModal('"
            . "$baseurl/event_templates/instantiate/$templateId', 'xl');",
        'icon' => 'fas fa-play',
        'label' => __('Create event from template'),
        'success' => true,
    ];
}

if ($this->Acl->canAccess('eventTemplates', 'preview')) {
    $actions[] = [
        'url' => "$baseurl/event_templates/preview/$templateId",
        'onclick' => "event.preventDefault(); openModal('"
            . "$baseurl/event_templates/preview/$templateId', 'xl');",
        'icon' => 'fas fa-eye',
        'label' => __('Preview the user form'),
    ];
}


if ($this->Acl->canAccess('eventTemplates', 'edit')) {
    $actions[] = [
        'url' => "$baseurl/event_templates/edit/$templateId",
        'onclick' => "event.preventDefault(); openModal('"
            . "$baseurl/event_templates/edit/$templateId', 'xl');",
        'icon' => 'fas fa-pen-to-square',
        'label' => __('Open in builder'),
    ];
}


if ($this->Acl->canAccess('eventTemplates', 'duplicate')) {
    $actions[] = [
        'url' => "$baseurl/event_templates/duplicate/$templateId",
        'onclick' => "event.preventDefault(); openModal('"
            . "$baseurl/event_templates/duplicate/$templateId', 'md');",
        'icon' => 'fas fa-copy',
        'label' => __('Duplicate'),
    ];
}

$actions[] = [
    'url' => "$baseurl/event_templates/export/$templateId",
    'icon' => 'fas fa-download',
    'label' => __('Export as JSON'),
];


if ($this->Acl->canAccess('eventTemplates', 'delete')) {
    $actions[] = [
        'url' => "$baseurl/event_templates/deleteSelection/$templateId",
        'onclick' => "event.preventDefault(); openModal('"
            . "$baseurl/event_templates/deleteSelection/$templateId', 'md');",
        'icon' => 'fas fa-trash',
        'label' => __('Delete template'),
        'danger' => true,
    ];
}

echo $this->element('genericElementsBS5/Cards/card_actions', [
    'actions' => $actions,
]);

// An inactive template cannot be instantiated — say why the button is missing.
if (!$isActive && $this->Acl->canAccess('eventTemplates', 'instantiate')): ?>
    <div class="card shadow-sm mb-3 border-0">
        <div class="card-body p-3 d-flex align-items-start gap-2 text-muted"
             style="font-size:.8rem;">
            <i class="fas fa-circle-info mt-1 text-secondary"></i>
            <div>
                <?= __('This template is inactive, so it cannot be used to create an event.') ?>
            </div>
        </div>
    </div>
<?php endif; ?>
