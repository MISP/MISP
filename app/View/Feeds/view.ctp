<?php
    $table_data = array();
    $table_data[] = array('key' => __('ID'), 'value' => $data['Feed']['id']);
    $table_data[] = array('key' => __('Name'), 'value' => $data['Feed']['name']);
    $table_data[] = array('key' => __('URL'), 'value' => $data['Feed']['url']);
    $table_data[] = array(
        'key' => __('Source format'),
        'html' => $data['Feed']['source_format'] !== 'misp' ? h($data['Feed']['source_format']) : sprintf(
            '%s%s',
            '<span class="blue bold">M</span>',
            '<span class="black bold">ISP</span>'
        )
    );
    if (!empty($data['Tag']['id'])) {
        $table_data[] = array(
            'key' => __('Tags'),
            'html' => sprintf(
                '<span class="eventTagContainer">%s</span>',
                $this->element(
                    'ajaxTags',
                    array(
                        'scope' => 'feed',
                        'tags' => array(array('Tag' => $data['Tag'])),
                        'tagAccess' => false,
                        'localTagAccess' => false,
                        'static_tags_only' => true
                    )
                )
            )
        );
    }
    $table_data[] = array('key' => __('Provider'), 'value' => $data['Feed']['provider']);
    $temp = json_decode($data['Feed']['rules'], true);
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
    if (!empty($data['Feed']['settings'])) {
        $table_data[] = array('key' => __('Settings'), 'html' => sprintf(
            '<pre class="red">%s</pre>',
            h(json_encode(json_decode($data['Feed']['settings']), JSON_PRETTY_PRINT)))
        );
    }
    $table_data[] = array('key' => __('Enabled'), 'boolean' => $data['Feed']['enabled']);
    $table_data[] = array('key' => __('Caching enabled'), 'boolean' => $data['Feed']['caching_enabled']);
    $progress_bar = sprintf(
        '<div class="progress" style="margin-bottom:0px;"><div class="bar" style="width: %s;">%s</div></div>',
        h($data['Feed']['coverage_by_other_feeds']),
        h($data['Feed']['coverage_by_other_feeds'])
    );
    $table_data[] = array(
        'key' => __('Coverage by other feeds'),
        'html' => $progress_bar
    );

//    $table_data[] = array('key' => __('Role'), 'html' => $this->Html->link($user['Role']['name'], array('controller' => 'roles', 'action' => 'view', $user['Role']['id'])));
    echo sprintf(
        '<div class="feeds view"><div class="row-fluid"><div class="span8" style="margin:0px;">%s<hr /><div class="feed_overlap_tool">%s</div></div></div></div>',
        sprintf(
            '<h2>%s</h2>%s',
            __('Feed'),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        $this->element('Feeds/View/feed_overlap_tool', array('other_feeds' => $other_feeds, 'feed' => $data))
    );
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'feeds', 'menuItem' => 'view'));
