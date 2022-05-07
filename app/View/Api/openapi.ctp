<?php
$this->viewVars['additionalJs'] = ['redoc.standalone'];
?>
<div id="redoc-container"></div>
<script>
    Redoc.init('/doc/openapi.yaml', {
        fontFamily: "inherit",
        disableSearch: true,
        expandResponses: "200"
    }, document.getElementById('redoc-container'))
</script> 
