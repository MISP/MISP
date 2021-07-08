<?php

echo $this->Form->input($fieldData['field'], $params);
?>
<div style="clear: both;">
    <span id="basicAuthFormEnable" class="btn btn-inverse quick-popover" style="line-height:10px; padding: 4px 4px;"><?php echo __('Add Basic Auth'); ?></span>
    <div id="basicAuthForm" class="quick-form" style="display:none;">
        <fieldset>
            <div class="input">
                <label for="BasicAuthUsername"><?php echo __('Username'); ?></label>
                <input class="form-control" type="text" id="BasicAuthUsername"><br />
            </div>
            <div class="input">
                <label for="BasicAuthPassword"><?php echo __('Password'); ?></label>
                <input class="form-control" type="text" id="BasicAuthPassword"><br />
            </div>
        </fieldset>
        <span class="btn-inverse btn" onClick="add_basic_auth();" style="line-height:10px; padding: 4px 4px;"><?php echo __('Add basic auth header'); ?></span>
    </div>
</div>
<br />
<script>
    $(document).ready(function() {
        $('#basicAuthFormEnable').click(function() {
            $('#basicAuthFormEnable').hide();
            $('#basicAuthForm').show();
        })
    });
</script>