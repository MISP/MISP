<?php 
    echo $this->element('genericElements/assetLoader', array(
        'js' => array('redoc.standalone')
    ));
?>
<div id="redoc-container" style="background-color: #f8f9fa;"></div>
<script>
    Redoc.init('/doc/openapi.yaml', {
        fontFamily: "inherit",
        disableSearch: true,
        expandResponses: "200"
    }, document.getElementById('redoc-container'))
</script> 
<style>
    html, body {
        scroll-behavior: auto !important;
    }
    .fixed-top {
        position: absolute !important;
    }
</style>