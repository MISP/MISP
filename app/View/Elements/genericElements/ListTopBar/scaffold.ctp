<div class="btn-toolbar" style="margin:0 10px;">
<?php
    foreach ($data['children'] as $group) {
        echo $this->element('/genericElements/ListTopBar/group_' . (empty($group['type']) ? 'simple' : $group['type']), array('data' => $group));
    }
?>
</div>
