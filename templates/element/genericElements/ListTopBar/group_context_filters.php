<?php
    $contextArray = [];
    foreach ($data['context_filters'] as $filteringContext) {
        $filteringContext['filterCondition'] = empty($filteringContext['filterCondition']) ? [] : $filteringContext['filterCondition'];
        $urlParams = [
            'controller' => $this->request->getParam('controller'),
            'action' => 'index',
            '?' => array_merge($filteringContext['filterCondition'], ['filteringLabel' => $filteringContext['label']])
        ];
        $currentQuery = $this->request->getQuery();
        $filteringLabel = !empty($currentQuery['filteringLabel']) ? $currentQuery['filteringLabel'] : '';
        $fakeFilteringLabel = !empty($fakeFilteringLabel) ? $fakeFilteringLabel : false;
        unset($currentQuery['page'], $currentQuery['limit'], $currentQuery['sort'], $currentQuery['filteringLabel']);
        if (!empty($filteringContext['filterCondition'])) { // PHP replaces `.` by `_` when fetching the request parameter
            $currentFilteringContext = [];
            foreach ($filteringContext['filterCondition'] as $currentFilteringContextKey => $value) {
                $currentFilteringContextKey = str_replace('.', '_', $currentFilteringContextKey);
                $currentFilteringContextKey = str_replace(' ', '_', $currentFilteringContextKey);
                $currentFilteringContext[$currentFilteringContextKey] = $value;
            }
        } else {
            $currentFilteringContext = $filteringContext['filterCondition'];
        }
        $contextItem = [
            'active' => (
                (
                    $currentQuery == $currentFilteringContext &&                // query conditions match
                    !isset($filteringContext['filterConditionFunction']) &&     // not a custom filtering
                    empty($filteringLabel) &&                                   // do not check `All` by default
                    empty($fakeFilteringLabel)                                  // no custom filter is a default filter
                ) ||
                $filteringContext['label'] == $filteringLabel ||                // labels should not be duplicated
                $filteringContext['label'] == $fakeFilteringLabel               // use the default filter
            ),
            'isFilter' => true,
            'onClick' => 'changeIndexContext',
            'onClickParams' => [
                'this',
                $this->Url->build($urlParams, [
                    'escape' => false, // URL builder escape `&` when multiple ? arguments
                ]),
                "#table-container-{$tableRandomValue}",
                "#table-container-{$tableRandomValue} table.table",
            ],
            'class' => 'btn-sm'
        ];
        if (!empty($filteringContext['viewElement'])) {
            $contextItem['html'] = $this->element(
                $filteringContext['viewElement'],
                $filteringContext['viewElementParams'] ?? []
            );
        } else {
            $contextItem['text'] = $filteringContext['label'];
        }
        $contextArray[] = $contextItem;
    }

    $dataGroup = [
        'type' => 'simple',
        'children' => $contextArray,
    ];
    if (isset($data['requirement'])) {
        $dataGroup['requirement'] = $data['requirement'];
    }
    echo '<div class="d-flex align-items-end topbar-contextual-filter">';
    echo $this->element('/genericElements/ListTopBar/group_simple', [
        'data' => $dataGroup,
        'tableRandomValue' => $tableRandomValue
    ]);
    echo '</div>';
?>

<script>
    function changeIndexContext(clicked, url, container, statusNode) {
        UI.reload(url, container, statusNode, [{
            node: clicked,
            config: {
                spinnerVariant: 'dark',
                spinnerType: 'grow',
                spinnerSmall: true
            }
        }])
    }
</script>