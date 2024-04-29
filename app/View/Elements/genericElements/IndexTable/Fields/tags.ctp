<?php
    $defaultParams = array(
        'searchScope' => isset($scope) ? $scope : '',
    );
    if (isset($field['elementParams'])) {
        $params = array_merge($defaultParams, $field['elementParams']);
    } else {
        $params = $defaultParams;
    }
    $tags = Hash::extract($row, $field['data_path']);
    if (!empty($tags)) {
        if (empty($tags[0])) {
            $tags = array($tags);
        }
        echo $this->element(
            'ajaxTags',
            [
                'scope' => $params['searchScope'],
                'attributeId' => 0,
                'tags' => $tags,
                'tagAccess' => false,
                'localTagAccess' => false,
                'static_tags_only' => 1,
                'scope' => isset($field['scope']) ? $field['scope'] : 'event',
                'hide_global_scope' => isset($field['hide_global_scope']) ? $field['hide_global_scope'] : false
            ]
        );
    } else if (!empty($field['includeTagCollection']) && empty($tags)) {
        if (!empty($row['TagCollection'])) {
            echo sprintf('<a class="badge" style="background-color: #fff; color: #000; border: 1px solid #000;" title="%s" href="%s">%s :: %s</a>',
                __('Tag Collection'),
                '/tag_collections/view/' . h($row['TagCollection'][0]['TagCollection']['id']),
                __('Tag Collection'),
                h($row['TagCollection'][0]['TagCollection']['name'])
            );
            echo '<div>';
            echo $this->element(
                'ajaxTags',
                [
                    'scope' => '',
                    'attributeId' => 0,
                    'tags' => Hash::extract($row['TagCollection'][0]['TagCollectionTag'], '{n}.Tag'),
                    'tagAccess' => false,
                    'localTagAccess' => false,
                    'static_tags_only' => 1,
                    'scope' => isset($field['scope']) ? $field['scope'] : 'event',
                    'hide_global_scope' => isset($field['hide_global_scope']) ? $field['hide_global_scope'] : false
                    ]
                );
            echo '</div>';
        }
    }
?>
