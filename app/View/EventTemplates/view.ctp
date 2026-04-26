<?php
$tpl = isset($data['EventTemplate']) ? $data['EventTemplate'] : [];
$org = isset($data['Organisation']) ? $data['Organisation'] : [];
$creator = isset($data['CreatorUser']) ? $data['CreatorUser'] : [];
$deps = isset($data['EventTemplateObjectDependency'])
    ? $data['EventTemplateObjectDependency']
    : [];

$distLabel = ((int)($tpl['distribution'] ?? 0) === 1)
    ? __('Community (all orgs on this instance)')
    : __('Your organisation only');

$table_data = [
    ['key' => __('ID'), 'value' => $tpl['id'] ?? ''],
    ['key' => __('Name'), 'value' => $tpl['name'] ?? ''],
    ['key' => __('UUID'), 'value' => $tpl['uuid'] ?? ''],
    ['key' => __('Organisation'), 'value' => $org['name'] ?? ''],
    ['key' => __('Creator'), 'value' => $creator['email'] ?? ''],
    ['key' => __('Distribution'), 'value' => $distLabel],
    ['key' => __('Active'), 'value' => ((int)($tpl['active'] ?? 0) === 1) ? __('Yes') : __('No')],
    ['key' => __('Version'), 'value' => $tpl['version'] ?? ''],
    ['key' => __('Created'), 'value' => $tpl['created'] ?? ''],
    ['key' => __('Modified'), 'value' => $tpl['modified'] ?? ''],
];
if (!empty($tpl['description'])) {
    $table_data[] = ['key' => __('Description'), 'value' => $tpl['description']];
}

$definitionJson = is_array($tpl['definition'] ?? null)
    ? JsonTool::encode($tpl['definition'], true)
    : (string)($tpl['definition'] ?? '');

$depRows = '';
if (!empty($deps)) {
    $depRows = '<table class="table table-striped table-condensed" style="margin-top:10px;">'
        . '<thead><tr>'
        . '<th>' . __('Object template name') . '</th>'
        . '<th>' . __('Object template UUID') . '</th>'
        . '<th>' . __('Minimum version') . '</th>'
        . '</tr></thead><tbody>';
    foreach ($deps as $dep) {
        $depRows .= sprintf(
            '<tr><td>%s</td><td><code>%s</code></td><td>%d</td></tr>',
            h($dep['object_template_name']),
            h($dep['object_template_uuid']),
            (int)$dep['minimum_version']
        );
    }
    $depRows .= '</tbody></table>';
} else {
    $depRows = '<em>' . __('None — this template does not reference any MISP objects.') . '</em>';
}

$templateId = (int)($tpl['id'] ?? 0);
$canEdit = $this->Acl->canAccess('eventTemplates', 'edit');
$canExport = $this->Acl->canAccess('eventTemplates', 'export');
$canInstantiate = $this->Acl->canAccess('eventTemplates', 'instantiate');

// Toolbar that floats next to the H2 title — "Export JSON" parity with
// Overmind's headerActions Export. Side menu still has the same link
// for keyboard-driven users; this is the discoverability hook.
$toolbarHtml = '';
if ($templateId > 0) {
    $btns = [];
    if ($canInstantiate) {
        $btns[] = sprintf(
            '<a href="%s" class="btn btn-primary"><i class="fa fa-play"></i> %s</a>',
            h($baseurl . '/event_templates/instantiate/' . $templateId),
            __('Create event from template')
        );
    }
    if ($canEdit) {
        $btns[] = sprintf(
            '<a href="%s" class="btn"><i class="fa fa-edit"></i> %s</a>',
            h($baseurl . '/event_templates/edit/' . $templateId),
            __('Edit')
        );
    }
    if ($canExport) {
        $btns[] = sprintf(
            '<a href="%s" class="btn" title="%s"><i class="fa fa-download"></i> %s</a>',
            h($baseurl . '/event_templates/export/' . $templateId),
            __('Download this template as a JSON file'),
            __('Export')
        );
    }
    if (!empty($btns)) {
        $toolbarHtml = '<div class="et-view-toolbar" style="float:right;margin-top:6px;">'
            . implode(' ', $btns)
            . '</div><div style="clear:both;"></div>';
    }
}

echo sprintf(
    '<div class="eventTemplates view"><div class="row-fluid"><div class="span10" style="margin:0px;">%s</div></div>%s</div>%s',
    sprintf(
        '%s<h2>%s</h2>%s<h3>%s</h3>%s<h3>%s</h3><pre style="max-height:500px;overflow:auto;">%s</pre>',
        $toolbarHtml,
        h($tpl['name'] ?? __('Event Template')),
        $this->element('genericElements/viewMetaTable', ['table_data' => $table_data]),
        __('Object template dependencies'),
        $depRows,
        __('Definition (JSON)'),
        h($definitionJson)
    ),
    '',
    $this->element('/genericElements/SideMenu/side_menu', [
        'menuList' => 'eventTemplates',
        'menuItem' => 'view',
    ])
);
?>
