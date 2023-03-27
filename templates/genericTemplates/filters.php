<?php

use Cake\Utility\Inflector;

$tableItems = array_map(function ($fieldName) {
    return [
        'fieldname' => $fieldName,
    ];
}, $filters);
$formTypeMap = $this->Form->getConfig('typeMap');

$filteringForm = $this->Bootstrap->table(
    [
        'small' => false,
        'striped' => false,
        'hover' => false,
        'tableClass' => ['indexFilteringTable'],
    ],
    [
        'fields' => [
            [
                'path' => 'fieldname', 'label' => __('Field'), 'formatter' => function ($field, $row) {
                    return sprintf('<span class="fieldName" data-fieldname="%s">%s</span>', h($field), h($field));
                }
            ],
            [
                'path' => 'operator', 'label' => __('Operator'), 'formatter' => function ($field, $row) use ($typeMap) {
                    $fieldName = $row['fieldname'];
                    $type = $typeMap[$fieldName] ?? 'text';
                    $options = [
                        sprintf('<option value="%s">%s</option>', '=', '='),
                        sprintf('<option value="%s">%s</option>', '!=', '!='),
                    ];
                    if ($type === 'datetime') {
                        $options = [
                            sprintf('<option value="%s">%s</option>', '>=', '>='),
                            sprintf('<option value="%s">%s</option>', '<=', '<='),
                        ];
                    }
                    return sprintf('<select class="fieldOperator form-select form-select-sm">%s</select>', implode('', $options));
                }
            ],
            [
                'path' => 'value',
                'labelHtml' => sprintf(
                    '%s %s',
                    __('Value'),
                    sprintf('<sup class="fa fa-info" title="%s"><sup>', __('Supports strict matches and LIKE matches with the `%` character.&#10;Example: `%.com`'))
                ),
                'formatter' => function ($field, $row) use ($typeMap, $formTypeMap, $filtersConfig) {
                    $fieldName = $row['fieldname'];
                    $formType = $formTypeMap[$typeMap[$fieldName]] ?? 'text';
                    $fieldData = [
                        'field' => $fieldName,
                        'type' => $formType,
                        'label' => '',
                        'class' => 'fieldValue form-control-sm'
                    ];
                    if (!empty($filtersConfig[$fieldName]['multiple'])) {
                        $fieldData['type'] = 'dropdown';
                        $fieldData['multiple'] = true;
                        $fieldData['select2'] = [
                            'tags' => true,
                            'tokenSeparators' => [',', ' '],
                        ];
                    }
                    $this->Form->setTemplates([
                        'formGroup' => '<div class="col-sm-10">{{input}}</div>',
                    ]);
                    return $this->element('genericElements/Form/fieldScaffold', [
                        'fieldData' => $fieldData,
                        'params' => []
                    ]);
                }
            ],
        ],
        'items' => $tableItems
    ]
);

$filteringMetafields = '';
if ($metaFieldsEnabled) {
    $helpText = $this->Bootstrap->node('sup', [
        'class' => ['ms-1 fa fa-info'],
        'title' => __('Include help'),
        'data-bs-toggle' => 'tooltip',
    ]);
    $filteringMetafields = $this->Bootstrap->node('h5', [], __('Meta Fields') . $helpText);
    $filteringMetafields .= $this->element('genericElements/IndexTable/metafield_filtering', $metaTemplates);
}

$filteringTags = '';
if ($taggingEnabled) {
    $helpText = $this->Bootstrap->node('sup', [
        'class' => ['ms-1 fa fa-info'],
        'title' => __('Supports negation matches (with the `!` character) and LIKE matches (with the `%` character).&#10;Example: `!exportable`, `%able`'),
        'data-bs-toggle' => 'tooltip',
    ]);
    $filteringTags = $this->Bootstrap->node('h5', [
        'class' => 'mt-2'
    ], __('Tags') . $helpText);
    $filteringTags .= $this->Tag->tags([], [
        'allTags' => $allTags,
        'picker' => true,
        'editable' => false,
    ]);
}

$modalBody = implode('', [$filteringForm, $filteringMetafields, $filteringTags]);

echo $this->Bootstrap->modal([
    'title' => __('Filtering options for {0}', Inflector::singularize($this->request->getParam('controller'))),
    'size' => !empty($metaFieldsEnabled) ? 'xl' : 'lg',
    'type' => 'confirm',
    'bodyHtml' => $modalBody,
    'confirmButton' => [
        'text' => __('Filter'),
    ],
    'confirmFunction' => 'filterIndex'
]);
?>

<script>
    $(document).ready(() => {
        const $filteringTable = $('table.indexFilteringTable')
        initFilteringTable($filteringTable)
    })

    function filterIndex(modalObject, tmpApi) {
        const controller = '<?= $this->request->getParam('controller') ?>';
        const action = 'index';
        const $tbody = modalObject.$modal.find('table.indexFilteringTable tbody')
        const $rows = $tbody.find('tr')
        const activeFilters = {}
        $rows.each(function() {
            const rowData = getDataFromRow($(this))
            let fullFilter = rowData['name']
            if (rowData['operator'] != '=') {
                fullFilter += ` ${rowData['operator']}`
            }
            if (rowData['value'].length > 0) {
                activeFilters[fullFilter] = rowData['value']
            }
        })
        if (modalObject.$modal.find('table.indexMetaFieldsFilteringTable').length > 0) {
            let metaFieldFilters = modalObject.$modal.find('table.indexMetaFieldsFilteringTable')[0].getFiltersFunction()
            metaFieldFilters = metaFieldFilters !== undefined ? metaFieldFilters : []
            for (let [metaFieldPath, metaFieldValue] of Object.entries(metaFieldFilters)) {
                activeFilters[metaFieldPath] = metaFieldValue
            }
        }
        $selectTag = modalObject.$modal.find('.tag-container select.select2-input')
        activeFilters['filteringTags'] = $selectTag.length > 0 ? $selectTag.select2('data').map(tag => tag.text) : []
        const searchParam = jQuery.param(activeFilters);
        const url = `/${controller}/${action}?${searchParam}`

        const randomValue = getRandomValue()
        UI.reload(url, $(`#table-container-${randomValue}`), $(`#table-container-${randomValue} table.table`), [{
            node: $(`#toggleFilterButton-${randomValue}`),
            config: {}
        }])
    }

    function initFilteringTable($filteringTable) {
        const $controlRow = $filteringTable.find('#controlRow')
        const randomValue = getRandomValue()
        const activeFilters = Object.assign({}, $(`#toggleFilterButton-${randomValue}`).data('activeFilters'))
        const tags = activeFilters['filteringTags'] !== undefined ? Object.assign({}, activeFilters)['filteringTags'] : []
        delete activeFilters['filteringTags']
        for (let [field, value] of Object.entries(activeFilters)) {
            const fieldParts = field.split(' ')
            let operator = '='
            if (fieldParts.length == 2) {
                operator = fieldParts[1]
                field = fieldParts[0]
            } else if (fieldParts.length > 2) {
                console.error('Field contains multiple spaces. ' + field)
            }
            setFilteringValues($filteringTable, field, value, operator)
        }
        if (tags.length > 0) {
            setFilteringTags($filteringTable, tags)
        }
    }

    function setFilteringValues($filteringTable, field, value, operator) {
        $row = $filteringTable.find('td > span.fieldName').filter(function() {
            return $(this).data('fieldname') == field
        }).closest('tr')
        $row.find('.fieldOperator').val(operator)
        const $formElement = $row.find('.fieldValue');
        if ($formElement.attr('type') === 'datetime-local') {
            $formElement.val(moment(value).format('yyyy-MM-DDThh:mm:ss'))
        } else if ($formElement.is('select') && Array.isArray(value)) {
            let newOptions = [];
            value.forEach(aValue => {
                const existingOption = $formElement.find('option').filter(function() {
                    return $(this).val() === aValue
                })
                if (existingOption.length == 0) {
                    newOptions.push(new Option(aValue, aValue, true, true))
                }
            })
            $formElement.append(newOptions).trigger('change');
        } else {
            $formElement.val(value)
        }
    }

    function setFilteringTags($filteringTable, tags) {
        $select = $filteringTable.closest('.modal-body').find('select.select2-input')
        let passedTags = []
        tags.forEach(tagname => {
            const existingOption = $select.find('option').filter(function() {
                return $(this).val() === tagname
            })
            if (existingOption.length == 0) {
                passedTags.push(new Option(tagname, tagname, true, true))
            }
        })
        $select
            .append(passedTags)
            .val(tags)
            .trigger('change')
    }

    function getDataFromRow($row) {
        const rowData = {};
        rowData['name'] = $row.find('td > span.fieldName').data('fieldname')
        rowData['operator'] = $row.find('select.fieldOperator').val()
        const $formElement = $row.find('.fieldValue');
        if ($formElement.attr('type') === 'datetime-local') {
            rowData['value'] = $formElement.val().length > 0 ? moment($formElement.val()).toISOString() : $formElement.val()
        } else {
            rowData['value'] = $formElement.val()
        }
        return rowData
    }

    function getRandomValue() {
        const $container = $('div[id^="table-container-"]')
        const randomValue = $container.attr('id').split('-')[2]
        return randomValue
    }
</script>