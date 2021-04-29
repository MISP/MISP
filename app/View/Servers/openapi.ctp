<?php 
    echo $this->element('genericElements/assetLoader', array(
        'js' => array('redoc.standalone')
    ));
?>
<div id="redoc-container"></div>
<script>
    Redoc.init('/doc/openapi.yaml', {
        fontFamily: "inherit"
    }, document.getElementById('redoc-container'))
</script>