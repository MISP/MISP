<?php

if(!function_exists("generateFilterLinkConfiguration")) {
    function generateFilterLinkConfiguration($filteringContext, $viewContext, $request, $tableRandomValue) {
        $filteringContext['filterCondition'] = empty($filteringContext['filterCondition']) ? [] : $filteringContext['filterCondition'];
        $urlParams = [
            'controller' => $request->getParam('controller'),
            'action' => 'index',
            '?' => array_merge($filteringContext['filterCondition'], ['filteringLabel' => $filteringContext['label']])
        ];
        $currentQuery = $request->getQuery();
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
                $viewContext->Url->build($urlParams, [
                    'escape' => false, // URL builder escape `&` when multiple ? arguments
                ]),
                "#table-container-{$tableRandomValue}",
                "#table-container-{$tableRandomValue} table.table",
            ],
            'class' => 'btn-sm'
        ];
        if (!empty($filteringContext['viewElement'])) {
            $contextItem['html'] = $viewContext->element(
                $filteringContext['viewElement'],
                $filteringContext['viewElementParams'] ?? []
            );
        } else {
            $contextItem['text'] = $filteringContext['label'];
        }
        return $contextItem;
    }
}


    $contextArray = [];
    foreach ($data['context_filters'] as $filteringContext) {
        if (!empty($filteringContext['is_group'])) {
            $groupHasOneLinkActive = false;
            $activeGroupName = null;
            $dropdownMenu = [];
            foreach ($filteringContext['filters'] as $filteringSubContext) {
                $linkContext = generateFilterLinkConfiguration($filteringSubContext, $this, $this->request, $tableRandomValue);
                if (!empty($linkContext['onClick']) || empty($linkContext['url'])) {
                    $onClickParams = [];
                    if (!empty($linkContext['onClickParams'])) {
                        $onClickParams = array_map(function($param) {
                            return $param === 'this' ? $param : sprintf('\'%s\'', $param);
                        }, $linkContext['onClickParams']);
                    }
                    $onClickParams = implode(',', $onClickParams);
                    $onClick = sprintf(
                        '%s%s',
                        (empty($linkContext['url'])) ? 'event.preventDefault();' : '',
                        (!empty($linkContext['onClick']) ? sprintf(
                            '%s(%s)',
                            h($linkContext['onClick']),
                            $onClickParams
                        ) : '')
                    );
                } else if(!empty($linkContext['url'])) {
                    $onClick = sprintf(
                        '%s',
                        sprintf('window.location=\'%s\'', $linkContext['url'])
                    );
                }
                if ($linkContext['active']) {
                    $groupHasOneLinkActive = true;
                    $activeGroupName = $filteringSubContext['label'];
                }
                $dropdownMenu[] = [
                    'text' => $filteringSubContext['label'],
                    'icon' => $filteringSubContext['icon'] ?? false,
                    'variant' => $linkContext['active'] ? 'primary' : '',
                    'attrs' => [
                        'onclick' => $onClick,
                    ],
                ];
            }
            $dropdownHtml = $this->Bootstrap->dropdownMenu([
                'button' => [
                    'icon' => $filteringContext['icon'] ?? false,
                    'text' => ($filteringContext['label'] ?? __('Quick Filters')) . ($groupHasOneLinkActive ? sprintf(': %s', $activeGroupName) : ''),
                    'variant' => $groupHasOneLinkActive ? 'primary' : ($filteringContext['variant'] ?? 'light'),
                ],
                'menu' => $dropdownMenu,
            ]);
            $contextArray[] = [
                'type' => 'raw_html',
                'html' => $dropdownHtml,
            ];
        } else {
            $contextArray[] = generateFilterLinkConfiguration($filteringContext, $this, $this->request, $tableRandomValue);
        }
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