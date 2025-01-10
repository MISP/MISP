<?php
// $tags = Hash::extract($data, $field['path']);
$tags = Hash::get($data, 'tags');
echo $this->Tag->tags($tags, [
    'allTags' => $allTags,
    'picker' => !empty($field['editable']),
    'editable' => !empty($field['editable']),
]);
