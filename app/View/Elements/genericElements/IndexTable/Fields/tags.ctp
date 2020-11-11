<?php
    $tags = Hash::extract($row, $field['data_path']);
    if (!empty($tags)) {
        if (empty($tags[0])) {
            $tags = array($tags);
        }
        echo $this->element(
            'ajaxTags',
            [
                'attributeId' => 0,
                'tags' => $tags,
                'tagAccess' => false,
                'static_tags_only' => 1,
                'scope' => isset($field['scope']) ? $field['scope'] : 'event',
                'hide_global_scope' => isset($field['hide_global_scope']) ? $field['hide_global_scope'] : false
            ]
        );
    }
?>
