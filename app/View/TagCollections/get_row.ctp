<?php
    echo $this->element('TagCollections/index_row');
?>

<script type="text/javascript">
    $(document).ready(function() {
        $('.addGalaxy').click(function() {
            addGalaxyListener(this);
        });
    });
</script>
