<?php
$this->set('headerIdentity', $data['EventTemplate'] ?? []);

$tpl = $data['EventTemplate'] ?? [];
$templateId = (int)($tpl['id'] ?? 0);

$definition = is_array($tpl['definition'] ?? null) ? $tpl['definition'] : [];
$structure = is_array($definition['structure'] ?? null)
    ? $definition['structure']
    : [];
$dependencies = $data['EventTemplateObjectDependency'] ?? [];

/*
 * Sections and text blocks lay the form out; everything else is something the
 * user filling the template has to answer, which is the number that describes
 * how heavy this template is.
 */
$sectionCount = 0;
$fieldCount = 0;
$mandatoryCount = 0;
foreach ($structure as $element) {
    $type = $element['type'] ?? '';
    if ($type === 'section') {
        $sectionCount++;
        continue;
    }
    if ($type === 'text_block') {
        continue;
    }
    $fieldCount++;
    if (!empty($element['mandatory'])) {
        $mandatoryCount++;
    }
}

$isActive = (int)($tpl['active'] ?? 0) === 1;

$descParts = [];
if (!empty($tpl['created'])) {
    $descParts[] = '<span title="' . h(__('Created')) . '"><i class="fas fa-calendar-plus me-1 opacity-50"></i>'
        . $this->Time->time($tpl['created']) . '</span>';
}
if (!empty($tpl['modified'])) {
    $descParts[] = '<span title="' . h(__('Last modified')) . '"><i class="fas fa-edit me-1 opacity-50"></i>'
        . $this->Time->time($tpl['modified']) . '</span>';
}
$this->set('headerTitle', $tpl['name'] ?? __('Event Template'));
$this->set('headerDescription', '<span class="d-inline-flex align-items-center gap-3 flex-wrap">' . implode('', $descParts) . '</span>');
$this->set('headerCountText', '');
$this->set('templateShape', [
    'sections' => $sectionCount,
    'fields' => $fieldCount,
    'mandatory' => $mandatoryCount,
    'dependencies' => count($dependencies),
]);

$tabs = [
    [
        'id' => 'general',
        'title' => __('General'),
        'icon' => 'fas fa-info-circle',
        'left' => [
            'eventTemplates/View/eventTemplate_general',
            'eventTemplates/View/eventTemplate_defaults',
        ],
        'right' => [
            'eventTemplates/View/eventTemplate_actions',
        ],
    ],
    [
        'id' => 'structure',
        'title' => __('Structure'),
        'icon' => 'fas fa-list-check',
        'count' => $fieldCount,
        'left' => [
            'eventTemplates/View/eventTemplate_structure',
        ],
    ],
    [
        'id' => 'dependencies',
        'title' => __('Dependencies'),
        'icon' => 'misp-icon misp-icon-object misp-simple',
        'count' => count($dependencies),
        'left' => [
            'eventTemplates/View/eventTemplate_dependencies',
        ],
    ],
    [
        'id' => 'definition',
        'title' => __('Definition'),
        'icon' => 'fas fa-code',
        'left' => [
            'eventTemplates/View/eventTemplate_definition',
        ],
    ],
];

echo $this->element('genericElementsBS5/Layout/view_layout', [
    'data' => $data,
    'ownership' => [
        'orgc' => $data['Organisation'] ?? [],
        'user' => $data['CreatorUser'] ?? [],
        'distribution' => $tpl['distribution'] ?? null,
    ],
    'tabs' => $tabs,
]);
