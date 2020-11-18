<?php
    echo sprintf('<div %s>', empty($ajax) ? 'class="index"' : '');
    echo $this->element('genericElements/IndexTable/index_table', $scaffold_data);
    echo '</div>';
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
    }
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    $(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
