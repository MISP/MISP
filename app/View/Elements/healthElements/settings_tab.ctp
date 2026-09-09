<?php
    // A tab with a single group renders it as one table; the group is `general`
    // except for a tab whose settings carry a plugin subGroup (the AI tab).
    $singleGroup = count($finalSettings) === 1 ? (string)key($finalSettings) : 'general';
    if (count($finalSettings) > 1) {
        echo $this->element('healthElements/settings_table_composition', array('finalSettings' => $finalSettings));
    } else {
        echo $this->element('healthElements/settings_table', array('settings' => $finalSettings[$singleGroup], 'subGroup' => $singleGroup));
    }
?>
<script type="text/javascript">
    $(document).ready(function() {
        $('.subGroup_<?= h($singleGroup) ?>').show();
    });
</script>
