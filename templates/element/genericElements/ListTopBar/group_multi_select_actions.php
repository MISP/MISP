<?php
    $dropdownTreshold = 3;

    if (!isset($data['requirement']) || $data['requirement']) {
        $buttons = '';
        $hasHeader = array_filter($data['children'], function($entry) {
            return !empty($entry['is-header']);
        });
        $data['force-dropdown'] = !empty($data['force-dropdown']) ? $data['force-dropdown'] : $hasHeader;
        if (!empty($data['force-dropdown']) || count($data['children']) > $dropdownTreshold) {
            $menuOptions = [];
            foreach ($data['children'] as $child) {
                $menuOptions[] = [
                    'header' => !empty($child['is-header']),
                    'variant' => $child['variant'] ?? '',
                    'text' => $child['text'],
                    'outline' => !empty($child['outline']),
                    'icon' => $child['icon'] ?? null,
                    'class' => $child['class'] ?? '',
                    'attrs' => array_merge([
                        'onclick' => 'multiActionClickHandler(this)',
                        'data-onclick-function' => $child['onclick'] ?? '',
                        'data-table-random-value' => $tableRandomValue,
                    ], $child['params'] ?? [])
                ];
            }
            $buttons = $this->Bootstrap->dropdownMenu([
                'button' => [
                    'text' => __('Actions'),
                    'icon' => 'check-square',
                    'variant' => 'primary',
                    'class' => [''],
                ],
                'attrs' => [
                    'data-table-random-value' => $tableRandomValue,
                ],
                'menu' => $menuOptions,
            ]);
        } else {
            foreach ($data['children'] as $child) {
                $buttons .= $this->Bootstrap->button([
                    'variant' => $child['variant'] ?? 'primary',
                    'text' => $child['text'],
                    'outline' => !empty($child['outline']),
                    'icon' => $child['icon'] ?? null,
                    'class' => $child['class'] ?? '',
                    'onclick' => 'multiActionClickHandler(this)',
                    'attrs' => array_merge([
                        'data-onclick-function' => $child['onclick'] ?? '',
                        'data-table-random-value' => $tableRandomValue,
                    ], $child['params'] ?? [])
                ]);
            }
        }
        echo sprintf(
            '<div class="multi_select_actions btn-group me-2 flex-wrap collapse" role="group" aria-label="button-group" data-table-random-value="%s">%s</div>',
            $tableRandomValue,
            $buttons
        );
    }
?>

<script type="text/javascript">
    $(document).ready(function() {
        let $table = $('#index-table-<?= $tableRandomValue ?>')
        $table.find('input.select_all').on('change', function() {
            toggleMultiSelectActions($table)
            
        });
        $table.find('input.selectable_row').on('change', function() {
            toggleMultiSelectActions($table)
            
        });
    });

    function toggleMultiSelectActions($table) {
        const randomValue = $table.data('table-random-value');
        let $multiSelectActions = $('div.multi_select_actions').filter(function() {
            return $(this).data('table-random-value') == randomValue
        })
        if (getSelected($table).length > 0) {
            $multiSelectActions.show()
        } else {
            $multiSelectActions.hide()
        }
    }

    function getSelected($table) {
        return $table.find('input.selectable_row:checked')
    }

    function multiActionClickHandler(clicked) {
        let $clicked = $(clicked)
        const randomValue = $clicked.data('table-random-value')
        let $table = $(`#index-table-${randomValue}`)
        let rowDataByID = {}
        $table.data('data').forEach(row => {
            rowDataByID[row.id] = row
        })
        const $selected = getSelected($table)
        let selectedIDs = []
        let selectedData = []
        $selected.each(function() {
            const dataID = $(this).data('id')
            selectedIDs.push(dataID)
            selectedData.push(rowDataByID[dataID])
        })
        const functionName = $clicked.data('onclick-function')
        if (functionName && typeof window[functionName] === 'function') {
            window[functionName](selectedIDs, selectedData, $table, $clicked)
        }
    }
</script>