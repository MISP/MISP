<?php
    if (!empty($event['Related' . $scope][$object['id']])) {
        $i = 0;
        $linkColour = $scope === 'Attribute' ? 'red' : 'white';
        $withPivot = isset($withPivot) ? $withPivot : false;
        // remove duplicates
        $relatedEvents = array();
        foreach ($event['Related' . $scope][$object['id']] as $k => $relatedAttribute) {
            if (isset($relatedEvents[$relatedAttribute['id']])) {
                unset($event['Related' . $scope][$object['id']][$k]);
            } else {
                $relatedEvents[$relatedAttribute['id']] = true;
            }
        }
        $count = count($event['Related' . $scope][$object['id']]);
        foreach ($event['Related' . $scope][$object['id']] as $relatedAttribute) {
            if ($i == 4 && $count > 5) {
                $expandButton = __('Show %s more…', $count - 4);
                echo sprintf(
                    '<li class="no-side-padding correlation-expand-button useCursorPointer linkButton %s">%s</li> ',
                    $linkColour,
                    $expandButton
                );
            }
            $relatedData = array(
                'Orgc' => $orgTable[$relatedAttribute['org_id']] ?? 'N/A',
                'Date' => $relatedAttribute['date'] ?? 'N/A',
                'Event' => $relatedAttribute['info'],
                'Correlating Value' => $relatedAttribute['value']
            );
            $popover = '';
            foreach ($relatedData as $k => $v) {
                $popover .= '<b class="black">' . h($k) . '</b>: <span class="blue">' . h($v) . '</span><br>';
            }
            $relevantId = !isset($relatedAttribute['attribute_id']) ? $relatedAttribute['Event']['id'] : $relatedAttribute['id'];
            $link = $this->Html->link(
                $relevantId,
                    $withPivot ?
                            ['controller' => 'events', 'action' => 'view', $relevantId, true, $event['Event']['id']] :
                            ['controller' => 'events', 'action' => 'view', $relevantId],
                ['class' => ($relatedAttribute['org_id'] == $me['org_id']) ? $linkColour : 'blue']
            );
            echo sprintf(
                '<li class="no-side-padding %s" %s data-toggle="popover" data-content="%s" data-trigger="hover">%s&nbsp;</li>',
                ($i > 4 || $i == 4 && $count > 5) ? 'correlation-expanded-area' : '',
                ($i > 4 || $i == 4 && $count > 5) ? 'style="display:none;"' : '',
                h($popover),
                $link
            );

            $i++;
        }
        if ($i > 5) {
            echo sprintf(
                '<li class="no-side-padding correlation-collapse-button useCursorPointer linkButton %s" style="display:none;">%s</li> ',
                $linkColour,
                __('Collapse…')
            );
        }
    }
    if (!empty($object['correlation_exclusion'])) {
        echo sprintf(
            '<span class="red" title="%s">%s</span> ',
            __('The attribute value matches a correlation exclusion rule defined by a site-administrator for this instance. Click the magnifying glass to search for all occurrences of the value.'),
            __('Excluded.')
        );
    } else if (!empty($object['over_correlation'])) {
        echo sprintf(
            '<span class="red" title="%s">%s</span> ',
            __('The instance threshold for the maximum number of correlations for the given attribute value has been exceeded. Click the magnifying glass to search for all occurrences of the value.'),
            __('Too many correlations.')
        );
    }
    echo $this->Html->link(
        '',
        ['controller' => 'attributes', 'action' => 'search', 'value' => $object['value']],
        [
            'class' => 'fa fa-search black',
            'title' => __('Search for value'),
            'aria-label' => __('Search for value')
        ]
    );
