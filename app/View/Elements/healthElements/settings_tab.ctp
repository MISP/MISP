<?php
    if (count($finalSettings) > 1) {
        echo $this->element('healthElements/settings_table_composition', array('finalSettings' => $finalSettings));
    } else {
        echo $this->element('healthElements/settings_table', array('settings' => $finalSettings['general'], 'subGroup' => 'general'));
    }
?>
<script type="text/javascript">
    $(document).ready(function() {
        $('.subGroup_general').show();
    });
</script>
