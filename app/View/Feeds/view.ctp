<?php
    $table_data = array();
    $table_data[] = array('key' => __('Id'), 'value' => $feed['Feed']['id']);
    $table_data[] = array('key' => __('Name'), 'value' => $feed['Feed']['name']);
    $table_data[] = array('key' => __('URL'), 'value' => $feed['Feed']['url']);
    $table_data[] = array(
        'key' => __('Source format'),
        'html' => $feed['Feed']['source_format'] !== 'misp' ? h($feed['Feed']['source_format']) : sprintf(
            '%s%s',
            '<span class="blue bold">M</span>',
            '<span class="black bold">ISP</span>'
        )
    );
    if (!empty($feed['Tag']['id'])) {
        $table_data[] = array(
            'key' => __('Tags'),
            'html' => sprintf(
                '<span class="eventTagContainer">%s</span>',
                $this->element(
                    'ajaxTags',
                    array(
                        'event' => false,
                        'tags' => array(array('Tag' => $feed['Tag'])),
                        'tagAccess' => false,
                        'static_tags_only' => true
                    )
                )
            )
        );
    }
    $table_data[] = array('key' => __('Provider'), 'value' => $feed['Feed']['provider']);
    $temp = json_decode($feed['Feed']['rules'], true);
    if ($temp) {
        $scopes = array('tags', 'orgs');
        $booleanScopeColours = array('OR' => 'green', 'NOT' => 'red');
        $ruleDataFinal = '';
        $rule = array();
        foreach ($temp as $scope => $ruleData) {
            if (!empty($ruleData['OR']) || !empty($ruleData['NOT'])) {
                $rule[] = sprintf(
                    '<span class="bold">%s</span>:',
                    h(ucfirst($scope))
                );
                foreach ($ruleData as $booleanScope => $ruleValues) {
                    foreach ($ruleValues as $ruleValue) {
                        $rule[] = sprintf(
                            '&nbsp;&nbsp;<span class="%s">%s</span>',
                            $booleanScopeColours[$booleanScope],
                            h($ruleValue)
                        );
                    }
                }
            }
        }
        $table_data[] = array('key' => __('Rules'), 'html' => implode('<br />', $rule));
    }
    if (!empty($feed['Feed']['settings'])) {
        $table_data[] = array('key' => __('Settings'), 'html' => sprintf(
            '<pre class="red">%s</pre>',
            h(json_encode(json_decode($feed['Feed']['settings']), JSON_PRETTY_PRINT)))
        );
    }
    $table_data[] = array('key' => __('Enabled'), 'boolean' => $feed['Feed']['enabled']);
    $table_data[] = array('key' => __('Caching enabled'), 'boolean' => $feed['Feed']['caching_enabled']);
    $progress_bar = sprintf(
        '<div class="progress" style="margin-bottom:0px;"><div class="bar" style="width: %s;">%s</div></div>',
        h($feed['Feed']['coverage_by_other_feeds']),
        h($feed['Feed']['coverage_by_other_feeds'])
    );
    $table_data[] = array(
        'key' => __('Coverage by other feeds'),
        'html' => $progress_bar
    );

//    $table_data[] = array('key' => __('Role'), 'html' => $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])));
    echo sprintf(
        '<div class="feeds view"><div class="row-fluid"><div class="span8" style="margin:0px;">%s<hr /><div class="feed_overlap_tool">%s</div></div></div></div>%s',
        sprintf(
            '<h2>%s</h2>%s',
            __('Feed'),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        $this->element('Feeds/View/feed_overlap_tool', array('other_feeds' => $other_feeds, 'feed' => $feed)),
        $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'feeds', 'menuItem' => 'view'))
    );
?>
