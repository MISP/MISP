<?php
// $tags = Cake\Utility\Hash::extract($data, $field['path']);
$tags = Cake\Utility\Hash::get($data, 'tags');
echo $this->Tag->tags($tags, [
    'allTags' => $allTags,
    'picker' => true,
    'editable' => true,
]);
