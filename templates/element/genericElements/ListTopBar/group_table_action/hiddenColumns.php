<?php
$tableSettings['hidden_column'] = $tableSettings['hidden_column'] ?? [];

$availableColumnsHtml = '';
$availableColumns = [];
foreach ($table_data['fields'] as $field) {
    if (
        (!empty($field['element']) && $field['element'] === 'selector') ||
        !empty($field['_automatic_field'])
    ) {
        continue;
    }
    $fieldName = !empty($field['name']) ? $field['name'] : \Cake\Utility\Inflector::humanize($field['data_path']);
    $isVisible = !in_array(h(\Cake\Utility\Inflector::variable($fieldName)), $tableSettings['hidden_column']);
    $availableColumns[] = $fieldName;
    $availableColumnsHtml .= sprintf(
        '<div class="form-check">
            <input class="form-check-input" type="checkbox" value="" id="columnCheck-%s" data-columnname="%s" %s>
            <label class="form-check-label w-100 cursor-pointer font-monospace user-select-none" for="columnCheck-%s">
                %s
            </label>
        </div>',
        h(\Cake\Utility\Inflector::variable($fieldName)),
        h(\Cake\Utility\Inflector::variable($fieldName)),
        $isVisible ? 'checked' : '',
        h(\Cake\Utility\Inflector::variable($fieldName)),
        h($fieldName)
    );
}

$availableColumnsHtml = $this->Bootstrap->node('form', [
    'class' => ['visible-column-form', 'px-2 py-1'],
], $availableColumnsHtml);
echo $availableColumnsHtml;
?>

<script>
    (function() {
        const debouncedHiddenColumnSaver = debounce(mergeAndSaveSettings, 2000)
        const debouncedHiddenColumnSaverWithReload = debounce(mergeAndSaveSettingsWithReload, 2000)

        function attachListeners() {
            let debouncedFunctionWithReload = false,
                debouncedFunction = false // used to flush debounce function if dropdown menu gets closed
            $('form.visible-column-form, form.visible-meta-column-form').find('input').change(function() {
                const $dropdownMenu = $(this).closest(`[data-table-random-value]`)
                const tableRandomValue = $dropdownMenu.attr('data-table-random-value')
                const $container = $dropdownMenu.closest('div[id^="table-container-"]')
                const $table = $container.find(`table[data-table-random-value="${tableRandomValue}"]`)
                const table_setting_id = $dropdownMenu.data('table_setting_id');
                toggleColumn(this.getAttribute('data-columnname'), this.checked, $table)
                let tableSettings = {}
                tableSettings[table_setting_id] = genTableSettings($container)
                if ($(this).closest('form').hasClass('visible-meta-column-form')) {
                    debouncedFunctionWithReload = true
                    debouncedHiddenColumnSaverWithReload(table_setting_id, tableSettings, $table)
                } else {
                    debouncedFunction = true
                    debouncedHiddenColumnSaver(table_setting_id, tableSettings)
                }
            })

            const $dropdownMenu = $('form.visible-column-form, form.visible-meta-column-form').closest(`[data-table-random-value]`)
            const $rootDropdown = $dropdownMenu.find('[data-bs-toggle="dropdown"]:first')
            $rootDropdown[0].addEventListener('hidden.bs.dropdown', function() {
                if (debouncedFunctionWithReload) {
                    debouncedHiddenColumnSaver.cancel()
                    debouncedHiddenColumnSaverWithReload.flush()
                } else if (debouncedFunction) {
                    debouncedHiddenColumnSaver.flush()
                }
                debouncedFunction = false
                debouncedFunctionWithReload = false
            })
        }

        function toggleColumn(columnName, isVisible, $table) {
            if (isVisible) {
                $table.find(`th[data-columnname="${columnName}"],td[data-columnname="${columnName}"]`).show()
            } else {
                $table.find(`th[data-columnname="${columnName}"],td[data-columnname="${columnName}"]`).hide()
            }
        }

        function genTableSettings($container) {
            let tableSetting = {};
            const $hiddenColumns = $container.find('form.visible-column-form').find('input').not(':checked')
            const hiddenColumns = Array.from($hiddenColumns.map(function() {
                return $(this).data('columnname')
            }))
            tableSetting['hidden_column'] = hiddenColumns

            const $visibleMetaColumns = $container.find('form.visible-meta-column-form').find('input:checked')
            const visibleMetaColumns = Array.from($visibleMetaColumns.map(function() {
                const columnName = $(this).data('columnname')
                const split = columnName.split('-')
                return [
                    [split[1], split[2]]
                ]
            })).reduce((store, composedValue) => {
                let [templateId, fieldId] = composedValue
                if (store[templateId] === undefined) {
                    store[templateId] = [];
                }
                store[templateId].push(fieldId)
                return store
            }, {})
            tableSetting['visible_meta_column'] = visibleMetaColumns
            return tableSetting
        }

        $(document).ready(function() {
            addSupportOfNestedDropdown();
            const $form = $('form.visible-column-form, form.visible-meta-column-form')
            const $checkboxes = $form.find('input').not(':checked')
            const $dropdownMenu = $form.closest('.dropdown')
            const tableRandomValue = $dropdownMenu.attr('data-table-random-value')
            const $container = $dropdownMenu.closest('div[id^="table-container-"]')
            const $table = $container.find(`table[data-table-random-value="${tableRandomValue}"]`)
            $checkboxes.each(function() {
                toggleColumn(this.getAttribute('data-columnname'), this.checked, $table)
            })
            attachListeners()
            registerDebouncedFunction($container, debouncedHiddenColumnSaver)
            registerDebouncedFunction($container, debouncedHiddenColumnSaverWithReload)
        })
    })()
</script>