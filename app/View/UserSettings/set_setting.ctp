<?php
    echo sprintf(
        '<div class="usersetting form">%s<fieldset><legend>%s</legend>%s</fieldset>%s%s</div>',
        $this->Form->create('UserSetting'),
        __('Set User Setting'),
        sprintf(
            '%s%s%s',
            $this->Form->input(
                'user_id',
                array(
                    'div' => 'clear',
                    'class' => 'input input-xxlarge',
                    'options' => array($users),
                    'disabled' => count($users) === 1
                )
            ),
            $this->Form->input(
                'setting',
                array(
                    'div' => 'clear',
                    'class' => 'input input-xxlarge',
                    'options' => array_combine(array_keys($validSettings), array_keys($validSettings)),
                    'default' => $setting,
                    'disabled' => (boolean)$setting
                )
            ),
            $this->Form->input(
                'value',
                array(
                    'div' => 'clear',
                    'class' => 'input input-xxlarge',
                    'type' => 'textarea',
                )
            )
        ),
        $this->Form->button(__('Submit'), array('class' => 'btn btn-primary')),
        $this->Form->end()
    );
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'user_settings_set'));
?>
<script type="text/javascript">
    var validSettings = <?php echo json_encode($validSettings); ?>;
    $(document).ready(function() {
        loadUserSettingValue();
        changeUserSettingPlaceholder();
        $('#UserSettingSetting').on('change', function() {
            loadUserSettingValue();
            changeUserSettingPlaceholder();
        });
        $('#UserSettingUserId').on('change', function() {
            loadUserSettingValue();
            changeUserSettingPlaceholder();
        });
    });
    function loadUserSettingValue() {
        var user_id = $('#UserSettingUserId').val();
        var setting = $('#UserSettingSetting').val();
        $.ajax({
            type:"get",
            url: baseurl + "/user_settings/getSetting/" + user_id + "/" + setting,
            success: function (data, textStatus) {
                if (data === '[]') {
                    var data = '';
                } else {
                    data = JSON.parse(data);
                    data = JSON.stringify(data, undefined, 4);
                }
                $('#UserSettingValue').val(data);
            }
        });
    }

    function changeUserSettingPlaceholder() {
        var setting = $('#UserSettingSetting').val();
        if (setting in validSettings) {
            $('#UserSettingValue').attr("placeholder", "Example:\n" + JSON.stringify(validSettings[setting]["placeholder"], undefined, 4));
        }
    }
</script>
