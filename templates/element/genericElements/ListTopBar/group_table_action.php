<?php

use App\Utility\UI\IndexSetting;

if (empty($data['table_setting_id']) && empty($model)) {
    throw new Exception(__('`table_setting_id` must be set in order to use the `table_action` table topbar'));
}
$data['table_setting_id'] = !empty($data['table_setting_id']) ? $data['table_setting_id'] : IndexSetting::getIDFromTable($model);
$tableSettings = IndexSetting::getTableSetting($loggedUser, $data['table_setting_id']);
$compactDisplay = !empty($tableSettings['compact_display']);
$numberOfElement = $tableSettings['number_of_element'] ?? 20;

$availableColumnsHtml = $this->element('/genericElements/ListTopBar/group_table_action/hiddenColumns', [
    'table_data' => $table_data,
    'tableSettings' => $tableSettings,
    'table_setting_id' => $data['table_setting_id'],
]);

$metaTemplateColumnMenu = [];
if (!empty($meta_templates)) {
    $metaTemplateColumnMenu[] = ['header' => true, 'text' => __('Meta Templates'), 'icon' => 'object-group',];
    if (empty($meta_templates_enabled)) {
        $metaTemplateColumnMenu[] = ['header' => false, 'text' => __('- No enabled Meta Templates found -'), 'class' => ['disabled', 'muted']];
    } else {
        foreach ($meta_templates_enabled as $meta_template) {
            $numberActiveMetaField = !empty($tableSettings['visible_meta_column'][$meta_template->id]) ? count($tableSettings['visible_meta_column'][$meta_template->id]) : 0;
            $metaTemplateColumnMenu[] = [
                'text' => $meta_template->name,
                'sup' => $meta_template->version,
                'badge' => [
                    'text' => $numberActiveMetaField,
                    'variant' => 'secondary',
                    'title' => __n('{0} meta-field active for this meta-template', '{0} meta-fields active for this meta-template', $numberActiveMetaField, $numberActiveMetaField),
                ],
                'keepOpen' => true,
                'menu' => [
                    [
                        'html' => $this->element('/genericElements/ListTopBar/group_table_action/hiddenMetaColumns', [
                            'tableSettings' => $tableSettings,
                            'table_setting_id' => $data['table_setting_id'],
                            'meta_template' => $meta_template,
                        ])
                    ]
                ],
            ];
        }
    }
}
$indexColumnMenu = array_merge(
    [['header' => true, 'text' => sprintf('%s\'s fields', $this->request->getParam('controller'))]],
    [['html' => $availableColumnsHtml]],
    $metaTemplateColumnMenu
);

$compactDisplayHtml = $this->element('/genericElements/ListTopBar/group_table_action/compactDisplay', [
    'table_data' => $table_data,
    'tableSettings' => $tableSettings,
    'table_setting_id' => $data['table_setting_id'],
    'compactDisplay' => $compactDisplay,
]);
$numberOfElementHtml = $this->element('/genericElements/ListTopBar/group_table_action/numberOfElement', [
    'table_data' => $table_data,
    'tableSettings' => $tableSettings,
    'table_setting_id' => $data['table_setting_id'],
    'numberOfElement' => $numberOfElement,
]);
?>
<?php if (!isset($data['requirement']) || $data['requirement']) : ?>
    <?php
    $now = date("Y-m-d_H-i-s");
    $downloadFilename = sprintf('%s_%s.json', $data['table_setting_id'] ?? h($model), $now);
    echo $this->Bootstrap->dropdownMenu([
        'dropdown-class' => 'ms-1',
        'alignment' => 'end',
        'direction' => 'down',
        'button' => [
            'icon' => 'sliders-h',
            'variant' => 'primary',
            'class' => ['table_setting_dropdown_button'],
        ],
        'submenu_alignment' => 'end',
        'submenu_direction' => 'start',
        'attrs' => [
            'data-table-random-value' => $tableRandomValue,
            'data-table_setting_id' => $data['table_setting_id'],
        ],
        'menu' => [
            [
                'text' => __('Show/hide columns'),
                'icon' => 'eye-slash',
                'keepOpen' => true,
                'menu' => $indexColumnMenu,
            ],
            [
                'text' => __('Download'),
                'icon' => 'download',
                'attrs' => [
                    'onclick' => sprintf('downloadIndexTable(this, "%s")', $downloadFilename),
                ],
            ],
            [
                'html' => $compactDisplayHtml,
            ],
            [
                'html' => $numberOfElementHtml,
            ]
        ]
    ]);
    ?>
<?php endif; ?>

<script>
    $(document).ready(function() {
        const dropdownBtn = document.querySelector('button.table_setting_dropdown_button')
        dropdownBtn.addEventListener('hidden.bs.dropdown', function() {
            const $dropdownBtn = $(this)
            const debouncedFunctions = $dropdownBtn.data('debouncedFunctions')
            firePendingDebouncedFunctions(dropdownBtn)
        })
    })
</script>