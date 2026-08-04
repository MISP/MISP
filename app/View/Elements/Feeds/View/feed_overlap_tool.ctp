<?php
    $progress_bar = sprintf(
        '<div class="span11 progress" style="margin-left:0px;"><div id="feed_coverage_bar" class="bar" style="width: %s;">%s</div></div><div class="span1">&nbsp;</div><br /><br />',
        (empty($feed['Feed']['coverage_by_selected_feeds']) ? h($feed['Feed']['coverage_by_other_feeds']) : h($feed['Feed']['coverage_by_selected_feeds'])),
        (empty($feed['Feed']['coverage_by_selected_feeds']) ? h($feed['Feed']['coverage_by_other_feeds']) : h($feed['Feed']['coverage_by_selected_feeds']))
    );
    echo sprintf(
        '<h3>%s</h3><p class="bold">%s</p>%s',
        __('Feed coverage tool'),
        __('Coverage by currently selected sources: '),
        $progress_bar
    );
    $options = array(
        'Server' => array(
            'left' => array(), 'right' => array()
        ),
        'Feed' => array(
            'left' => array(), 'right' => array()
        )
    );
    //debug($other_feeds);
    foreach (array_keys($options) as $scope) {
        array_multisort(array_column($other_feeds[$scope], 'matching_values'), SORT_DESC, $other_feeds[$scope]);
    }
    foreach ($options as $scope => $temp) {
        if (!empty($other_feeds[$scope])) {
            foreach ($other_feeds[$scope] as $other_feed) {
                if (!empty($other_feed['exclude'])) {
                    $options[$scope]['right'][$other_feed['name']] = $other_feed;
                } else {
                    $options[$scope]['left'][$other_feed['name']] = $other_feed;
                }
            }
        }
    }
    foreach ($options as $scope => $data) {
        $temp = array('left' => array(), 'right' => array());
        foreach ($data as $side => $data_points) {
            if (!empty($data[$side])) {
                foreach ($data_points as $data_point) {
                    $temp[$side][] = sprintf(
                        '<option value=%s>%s</option>',
                        h($data_point['id']),
                        sprintf(
                            '[%s%%] %s',
                            round(100 * $data_point['matching_values'] / $feed['Feed']['cached_elements']),
                            h($data_point['name'])
                        )
                    );
                }
            }
        }
        echo sprintf(
            '<h4>%s</h4><div class="row-fluid"><div class="span5">%s</div><div class="span1" style="text-align:center;margin-top:50px;">%s</div><div class="span5">%s</div></div>',
            h($scope),
            sprintf(
                '<b class="bold">%s</b><select id="%s" class="picker-%s" style="width:100%%;" size="5" multiple="multiple" data-pickername="%s">%s</select>',
                __('Include'),
                h($scope) . 'Left',
                'left',
                h($scope),
                implode('', $temp['left'])
            ),
            sprintf(
                '<button class="btn btn-inverse btn-small" onclick="generic_picker_move(%s, %s);" title="Include selected">&lt;&lt;</button>
                <button class="btn btn-inverse btn-small" onclick="generic_picker_move(%s, %s);" title="Include selected">&gt;&gt;</button>',
                '\'' . h($scope) . '\'',
                "'left'",
                '\'' . h($scope) . '\'',
                "'right'"
            ),

            sprintf(
                '<b class="bold">%s</b><select id="%s" class="picker-%s" style="width:100%%;" size="5" multiple="multiple" data-pickername="%s">%s</select>',
                __('Exclude'),
                h($scope) . 'Right',
                'right',
                h($scope),
                implode('', $temp['right'])
            )
        );
    }
    echo sprintf(
        '<button class="btn btn-primary" onClick="submit_feed_overlap_tool(%s);">%s</button>',
        h($feed['Feed']['id']),
        __('Check coverage')
    );
