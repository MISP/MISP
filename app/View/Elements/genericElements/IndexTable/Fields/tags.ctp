<?php
    $defaultParams = array(
        'searchScope' => isset($scope) ? $scope : '',
    );
    if (isset($field['elementParams'])) {
        $params = array_merge($defaultParams, $field['elementParams']);
    } else {
        $params = $defaultParams;
    }
    $attributeId = 0;
    if (isset($field['id_data_path'])) {
        $attributeId = Hash::get($row, $field['id_data_path']);
    }
    $event = !empty($row['Event']) ? ['Event' => $row['Event']] : false;
    $tags = Hash::extract($row, $field['data_path']);
    if (!empty($tags)) {
        if (empty($tags[0])) {
            $tags = array($tags);
        }
        echo $this->element(
            'ajaxTags',
            [
                'scope' => $params['searchScope'],
                'attributeId' => $attributeId,
                'tags' => $tags,
                'tagAccess' => $isSiteAdmin || $mayModify,
                'localTagAccess' => $event !== false ? $this->Acl->canModifyTag($event, true) : false,
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
                    'attributeId' => $attributeId,
                    'tags' => Hash::extract($row['TagCollection'][0]['TagCollectionTag'], '{n}.Tag'),
                    'tagAccess' => $isSiteAdmin || $mayModify,
                    'localTagAccess' => $event !== false ? $this->Acl->canModifyTag($event, true) : false,
                    'static_tags_only' => 1,
                    'scope' => isset($field['scope']) ? $field['scope'] : 'event',
                    'hide_global_scope' => isset($field['hide_global_scope']) ? $field['hide_global_scope'] : false
                    ]
                );
            echo '</div>';
        }
    }
    if (!empty($field['addButtonOnly'])) {
        echo $this->element(
            'ajaxTags',
            [
                'scope' => isset($field['scope']) ? $field['scope'] : 'event',
                'attributeId' => $attributeId,
                'tags' => [],
                'tagAccess' => $isSiteAdmin || $mayModify,
                'localTagAccess' => $this->Acl->canModifyTag($event, true),
                'static_tags_only' => false,
                'scope' => isset($field['scope']) ? $field['scope'] : 'event',
                'hide_global_scope' => isset($field['hide_global_scope']) ? $field['hide_global_scope'] : false,
                'addButtonOnly' => !empty($field['addButtonOnly']),
            ]
        );
    }
?>
