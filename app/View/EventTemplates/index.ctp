<?php
echo '<div class="eventTemplates index">';
// Only show the welcoming empty state when the index is genuinely empty —
// not when a filter merely returned zero rows. The latter is left to the
// IndexTable's standard "no matching records" rendering so we don't mislead
// users who just typed something into the search box.
$indexFilters = isset($this->request->params['named']) ? $this->request->params['named'] : array();
$indexQuery = isset($this->request->query) ? $this->request->query : array();
$filterActive = !empty($indexFilters) || !empty($indexQuery);
$emptyState = empty($list) && !$filterActive;
if ($emptyState) {
    $canAdd = $this->Acl->canAccess('eventTemplates', 'add');
    $canImport = $this->Acl->canAccess('eventTemplates', 'import');
    $cta = '';
    if ($canAdd) {
        $cta .= sprintf(
            '<a href="%s" class="btn btn-primary"><i class="fa fa-plus"></i> %s</a> ',
            h($baseurl . '/event_templates/add'),
            __('Add your first template')
        );
    }
    if ($canImport) {
        $cta .= sprintf(
            '<a href="%s" class="btn"><i class="fa fa-upload"></i> %s</a>',
            h($baseurl . '/event_templates/import'),
            __('Import from JSON')
        );
    }
    echo sprintf(
        '<div class="alert alert-info" style="margin-top:14px;">'
        . '<h4 style="margin-top:0;">%s</h4>'
        . '<p>%s</p>'
        . ($cta !== '' ? '<p style="margin-bottom:0;">' . $cta . '</p>' : '')
        . '</div>',
        __('No event templates yet'),
        __('Event templates let your team scaffold a consistent event for a recurring incident type — '
            . 'the creator authors the structure once (sections, attribute fields, MISP objects, '
            . 'tags, galaxies), and other users fill in just the values for each new event.')
    );
}
echo $this->element('/genericElements/IndexTable/index_table', [
    'data' => [
        'title' => __('Event Templates'),
        'data' => $list,
        'top_bar' => [
            'children' => [
                [
                    'type' => 'simple',
                    'children' => [
                        [
                            'active' => true,
                            'url' => $baseurl . '/event_templates/add',
                            'icon' => 'plus',
                            'text' => __('Add Event Template'),
                            'requirement' => $this->Acl->canAccess('eventTemplates', 'add'),
                        ],
                        [
                            'url' => $baseurl . '/event_templates/import',
                            'icon' => 'upload',
                            'text' => __('Import'),
                            'requirement' => $this->Acl->canAccess('eventTemplates', 'import'),
                        ],
                        [
                            'url' => $baseurl . '/event_templates/update',
                            'icon' => 'sync',
                            'text' => __('Update from library'),
                            'title' => __('Reconcile event_templates with the bundled misp-event-templates submodule (site-admin only).'),
                            'requirement' => $this->Acl->canAccess('eventTemplates', 'update'),
                        ],
                    ],
                ],
                [
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'data' => '',
                    'searchKey' => 'searchall',
                ],
            ],
        ],
        'fields' => [
            [
                'name' => __('ID'),
                'sort' => 'EventTemplate.id',
                'class' => 'short',
                'data_path' => 'EventTemplate.id',
            ],
            [
                'name' => __('Name'),
                'sort' => 'EventTemplate.name',
                'class' => 'shortish',
                'data_path' => 'EventTemplate.name',
            ],
            [
                'name' => __('UUID'),
                'sort' => 'EventTemplate.uuid',
                'class' => 'short',
                'element' => 'shortUUID',
                'data_path' => 'EventTemplate.uuid',
                'object_type' => 'EventTemplate',
            ],
            [
                'name' => __('Organisation'),
                'sort' => 'Organisation.name',
                'class' => 'short',
                'element' => 'org',
                'data_path' => 'Organisation',
            ],
            [
                'name' => __('Distribution'),
                'sort' => 'EventTemplate.distribution',
                'class' => 'short',
                'data_path' => 'EventTemplate.distribution',
                'element' => 'generic_field',
                'mapping' => [
                    0 => __('Org only'),
                    1 => __('Community'),
                ],
            ],
            [
                'name' => __('Active'),
                'sort' => 'EventTemplate.active',
                'class' => 'short',
                'element' => 'boolean',
                'data_path' => 'EventTemplate.active',
            ],
            [
                'name' => __('Version'),
                'sort' => 'EventTemplate.version',
                'class' => 'short',
                'data_path' => 'EventTemplate.version',
            ],
            [
                'name' => __('Modified'),
                'sort' => 'EventTemplate.modified',
                'class' => 'short',
                'element' => 'datetime',
                'data_path' => 'EventTemplate.modified',
            ],
        ],
        'actions' => [
            [
                'url' => $baseurl . '/event_templates/view',
                'url_params_data_paths' => ['EventTemplate.id'],
                'icon' => 'eye',
                'title' => __('View'),
            ],
            [
                'url' => $baseurl . '/event_templates/instantiate',
                'url_params_data_paths' => ['EventTemplate.id'],
                'icon' => 'play',
                'title' => __('Create event from template'),
                'requirement' => $this->Acl->canAccess('eventTemplates', 'instantiate'),
            ],
            [
                'url' => $baseurl . '/event_templates/edit',
                'url_params_data_paths' => ['EventTemplate.id'],
                'icon' => 'edit',
                'title' => __('Edit'),
                'requirement' => $this->Acl->canAccess('eventTemplates', 'edit'),
            ],
            [
                'url' => $baseurl . '/event_templates/duplicate',
                'url_params_data_paths' => ['EventTemplate.id'],
                'postLink' => '',
                'postLinkConfirm' => __('Duplicate this template into a new one owned by your org?'),
                'icon' => 'copy',
                'title' => __('Duplicate'),
                'requirement' => $this->Acl->canAccess('eventTemplates', 'duplicate'),
            ],
            [
                'url' => $baseurl . '/event_templates/export',
                'url_params_data_paths' => ['EventTemplate.id'],
                'icon' => 'download',
                'title' => __('Export'),
            ],
            [
                'url' => $baseurl . '/event_templates/delete',
                'url_params_data_paths' => ['EventTemplate.id'],
                'postLink' => '',
                'postLinkConfirm' => __('Are you sure you want to delete this event template?'),
                'icon' => 'trash',
                'title' => __('Delete'),
                'requirement' => $this->Acl->canAccess('eventTemplates', 'delete'),
            ],
        ],
    ],
]);
echo '</div>';
echo $this->element('/genericElements/SideMenu/side_menu', [
    'menuList' => 'eventTemplates',
    'menuItem' => 'index',
]);
?>
<script type="text/javascript">
    $(document).ready(function () {
        $('#quickFilterButton').click(function () {
            runIndexQuickFilter();
        });
    });
</script>
