<?php
    $tags = Hash::extract($row, $field['data_path']);
    if (!empty($tags)) {
        if (empty($tags[0])) {
            $tags = array($tags);
        }
        echo $this->element(
            'ajaxTags',
            array(
                'attributeId' => 0,
                'tags' => $tags,
                'tagAccess' => false
            )
        );
    }
?>
