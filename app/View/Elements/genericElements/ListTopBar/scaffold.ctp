<?php
    $groups = '';
    foreach ($data['children'] as $group) {
        $groups .= $this->element('/genericElements/ListTopBar/group_' . (empty($group['type']) ? 'simple' : h($group['type'])), array('data' => $group));
    }
    echo sprintf(
        '<div class="btn-toolbar" style="margin:0px 10px;">%s</div>',
        $groups
    );
?>
