<div id="temp"></div>
<?php echo $this->element('generic_picker'); ?>
<script>
    $(document).ready(function() {
        $('#GalaxyAttributeIds').attr('value', getSelected());
    });
</script>
