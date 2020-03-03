<?php
    $tags = Hash::extract($row, $field['data_path']);
    echo $this->element('ajaxTags', array('attributeId' => 0, 'tags' => $tags, 'tagAccess' => false));
?>
