<?php
$data = Hash::extract($row, $field['data_path']);
if (!empty($data)) { 
    foreach ($data as $group => $requirements) {
        echo '<span class="bold">' . h($group) . '</span><br />';
        foreach ($requirements as $requirement) {
            echo '<span>&nbsp;&nbsp;' . h($requirement) . '</span><br />';
        }
    }
}
?>
