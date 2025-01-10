<?php
$filteringItems = [];
foreach ($metaTemplates as $template_id => $metaTemplate) {
    foreach ($metaTemplate['meta_template_fields'] as $metaTemplateField) {
        $filteringItems[h($metaTemplate->name)][] = [
            'id' => h($metaTemplateField->id),
            'name' => h($metaTemplateField->field),
            'template_id' => h($template_id),
            'type' => h($metaTemplateField->type),
        ];
    }
}

$filteringForm = $this->Bootstrap->table(
    [
        'small' => true,
        'striped' => false,
        'hover' => false,
        'tableClass' => ['indexMetaFieldsFilteringTable'],
    ],
    [
        'fields' => [
            __('Meta Field'),
            __('Operator'),
            [
                'labelHtml' => sprintf(
                    '%s %s',
                    __('Value'),
                    sprintf('<sup class="fa fa-info" title="%s"><sup>', __('Supports strict matches and LIKE matches with the `%` character.&#10;Example: `%.com`'))
                )
            ],
            __('Action')
        ],
        'items' => []
    ]
);
?>

<?= $filteringForm; ?>
<script>
    (function() {
        const availableFilters = <?= json_encode($filteringItems) ?>;
        const typeHandlersOperators = <?= json_encode($typeHandlersOperators) ?>;

        $(document).ready(() => {
            const $filteringTable = $('table.indexMetaFieldsFilteringTable')
            initFilteringTable($filteringTable)
        })

        function initFilteringTable($filteringTable) {
            $filteringTable.find('tbody').empty()
            $filteringTable[0].getFiltersFunction = getFilters
            addControlRow($filteringTable)
            const randomValue = getRandomValue()
            const activeFilters = Object.assign({}, $(`#toggleFilterButton-${randomValue}`).data('activeFilters'))
            const metaFields = activeFilters['filteringMetaFields'] !== undefined ? Object.assign({}, activeFilters)['filteringMetaFields'] : []
            metaFields.forEach(metaField => {
                addFilteringRow($filteringTable, metaField.meta_template_field_id, metaField.value, '=')
            })
        }

        function addControlRow($filteringTable) {
            const $selectField = genMetaFieldsSelectElement()
                .val(null).trigger('change')
            const $selectOperator = $('<select/>').addClass('fieldOperator form-select form-select-sm')
                .append([
                    $('<option/>').text('=').val('='),
                    $('<option/>').text('!=').val('!='),
                ])
            const $row = $('<tr/>').attr('id', 'controlRow')
                .append(
                    $('<td/>').append($selectField),
                    $('<td/>').append($selectOperator),
                    $('<td/>').append(
                        $('<input>').attr('type', 'text').addClass('fieldValue form-control form-control-sm')
                    ),
                    $('<td/>').append(
                        $('<button/>').attr('type', 'button').addClass('btn btn-sm btn-primary')
                        .append($('<span/>').addClass('fa fa-plus'))
                        .click(addFiltering)
                    )
                )
            $filteringTable.append($row)
            enableSelect2($selectField, $filteringTable.closest('.modal'))
        }

        function enableSelect2($select, $dropdownParent) {
            $select.select2({
                dropdownParent: $dropdownParent,
                placeholder: '<?= __('Pick a meta field') ?>',
                allowClear: true,
                templateSelection: select2FormatState,
            })
        }

        function select2FormatState(state) {
            if (!state.id) {
                return state.text;
            }
            const selectedData = $(state.element).data('meta_template_data')
            const $state = $('<span/>').append(
                $('<span/>').addClass('fw-light fs-8 me-1').text(`${selectedData.template_name} ::`),
                $('<span/>').text(selectedData.template_field_name)
            )
            return $state
        }

        function addFilteringRow($filteringTable, field, value, operator) {
            const $selectField = genMetaFieldsSelectElement()
            $selectField.val(field).trigger('change.select2');
            const $selectOperator = $('<select/>').addClass('fieldOperator form-select form-select-sm')
                .append([
                    $('<option/>').text('=').val('='),
                    $('<option/>').text('!=').val('!='),
                ]).val(operator)
            const $row = $('<tr/>')
                .append(
                    $('<td/>').append($selectField),
                    $('<td/>').append($selectOperator),
                    $('<td/>').append(
                        $('<input>').attr('type', 'text').addClass('fieldValue form-control form-control-sm').val(value)
                    ),
                    $('<td/>').append(
                        $('<button/>').attr('type', 'button').addClass('btn btn-sm btn-danger')
                        .append($('<span/>').addClass('fa fa-trash'))
                        .click(removeSelf)
                    )
                )
            $filteringTable.append($row)
            enableSelect2($selectField, $filteringTable.closest('.modal'))
        }

        function addFiltering() {
            const $table = $(this).closest('table.indexMetaFieldsFilteringTable')
            const $controlRow = $table.find('#controlRow')
            const field = $controlRow.find('select.fieldSelect').val()
            const value = $controlRow.find('input.fieldValue').val()
            const operator = $controlRow.find('select.fieldOperator').val()
            addFilteringRow($table, field, value, operator)
            $controlRow.find('input.fieldValue').val('')
            $controlRow.find('select.fieldSelect').val('').trigger('change.select2');
        }

        function removeSelf() {
            const $row = $(this).closest('tr')
            const $controlRow = $row.closest('table.indexMetaFieldsFilteringTable').find('#controlRow')
            const field = $row.data('fieldName')
            $row.remove()
        }

        function genMetaFieldsSelectElement() {
            const $selectField = $('<select/>').addClass('fieldSelect form-select form-select-sm')
            for (let [metaTemplateName, metaTemplateFields] of Object.entries(availableFilters)) {
                $selectField.append($('<optgroup/>').attr('label', metaTemplateName));
                metaTemplateFields.forEach(metaTemplateField => {
                    $selectField.append($('<option/>')
                        .val(metaTemplateField['id'])
                        .text(metaTemplateField['name'])
                        .data('meta_template_data', {
                            template_id: metaTemplateField['template_id'],
                            template_field_id: metaTemplateField['id'],
                            template_name: metaTemplateName,
                            template_field_name: metaTemplateField['name'],
                            template_field_type: metaTemplateField['type'],
                        })
                    )
                });
            }
            $selectField.change(function() {
                if ($(this).data('select2') !== undefined) {
                    const pickedType = $($(this).select2('data')[0].element).data('meta_template_data')['template_field_type']
                    let operators = typeHandlersOperators[pickedType]
                    if (operators === undefined || operators.length == 0) {
                        operators = ['=', '!=']
                    }
                    // setMetaFieldsSelectOperators($(this), operators)
                }
            })
            return $selectField
        }

        // /* Unused - Might be useful in the future if wee need to change the operators. Right now = and != are enough */
        // function setMetaFieldsSelectOperators($fieldSelect, operators) {
        //     const $table = $fieldSelect.closest('table.indexMetaFieldsFilteringTable')
        //     const $controlRow = $table.find('#controlRow')
        //     const $operatorSelect = $controlRow.find('select.fieldOperator')
        //     $operatorSelect.empty()
        //     operators.forEach((operator) => {
        //         $operatorSelect.append($('<option/>').text(operator).val(operator), )
        //     })
        //     $operatorSelect.val(operators[0])
        // }

        function getFilters() {
            const $table = $(this)
            let activeFilters = [];
            $table.find('tbody tr').each(function() {
                const $row = $(this)
                if ($row.find('select.fieldSelect').select2('data').length > 0) {
                    let rowData = {}
                    selectedData = $($row.find('select.fieldSelect').select2('data')[0].element).data('meta_template_data')
                    rowData['name'] = `_metafield.${selectedData.template_id}.${selectedData.template_field_id}`
                    rowData['operator'] = $row.find('select.fieldOperator').val()
                    rowData['value'] = $row.find('input.fieldValue').val()
                    let fullFilter = rowData['name']
                    if (rowData['operator'] == '!=') {
                        fullFilter += ' !='
                    }
                    if (rowData['value'].length > 0) {
                        activeFilters[fullFilter] = rowData['value']
                    }
                }
            })
            return activeFilters
        }
    }())
</script>