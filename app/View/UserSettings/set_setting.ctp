<?php
    echo sprintf(
        '<div class="usersetting form">%s<fieldset><legend>%s</legend>%s</fieldset>%s%s</div>',
        $this->Form->create('UserSetting'),
        __('Set User Setting'),
        sprintf(
            '%s%s%s%s',
            $this->Form->input(
                'user_id',
                array(
                    'div' => 'clear',
                    'class' => 'input input-xxlarge',
                    'options' => $users,
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
                    'required' => false,
                )
            ),
            $this->Form->input(
                'value_select',
                array(
                    'label' => __('Value'),
                    'div' => 'clear',
                    'class' => 'input input-xxlarge',
                    'default' => isset($current_setting) ? $current_setting : null,
                    'options' => !empty($validSettings[$setting]['options']) ? $validSettings[$setting]['options'] : [],
                )
            )
        ),
        $this->Form->button(__('Submit'), array('class' => 'btn btn-primary')),
        $this->Form->end()
    );
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'user_settings_set'));
?>
<script type="text/javascript">
    var validSettings = <?= json_encode($validSettings); ?>;

    $(function() {
        $('#UserSettingValueSelect').parent().hide();
        loadUserSettingValue();
        changeUserSettingPlaceholder();
        $('#UserSettingSetting, #UserSettingUserId').on('change', function() {
            loadUserSettingValue();
            changeUserSettingPlaceholder();
        });
        $('#UserSettingValueSelect').on('change', function() {
            $('#UserSettingValue').val($(this).val());
        });
    });

    function loadUserSettingValue() {
        var user_id = $('#UserSettingUserId').val();
        var setting = $('#UserSettingSetting').val();
        $.ajax({
            type: "get",
            url: baseurl + "/user_settings/getSetting/" + user_id + "/" + setting + ".json",
            success: function (data) {
                var value = data['UserSetting']['value'];
                if (typeof value === 'object' && value !== null) {
                    $('#UserSettingValue').val(JSON.stringify(value, undefined, 4));
                } else {
                    $('#UserSettingValue').val(value);
                }
                if ($('#UserSettingValueSelect').is(':visible')) {
                    $('#UserSettingValueSelect').val(value);
                }
            },
            error: function (xhr) {
                if (xhr.status === 404) {
                    $('#UserSettingValue').val('');
                    if ($('#UserSettingValueSelect').is(':visible')) {
                        $('#UserSettingValueSelect').val('');
                    }
                } else {
                    xhrFailCallback(xhr);
                }
            }
        });
    }

    function changeUserSettingPlaceholder() {
        var setting = $('#UserSettingSetting').val();
        if (setting in validSettings) {
            $('#UserSettingValue').attr("placeholder", "Example:\n" + JSON.stringify(validSettings[setting]["placeholder"], undefined, 4));
            if ('options' in validSettings[setting]) {
                $('#UserSettingValueSelect').empty();
                validSettings[setting]['options'].forEach(function(option) {
                    $('#UserSettingValueSelect').append($('<option>', {
                        value: option,
                        text: option
                    }));
                });
                $('#UserSettingValueSelect').prop('selectedIndex', 0);
                $('#UserSettingValueSelect').parent().show();
                $('#UserSettingValue').parent().hide();
            } else {
                $('#UserSettingValueSelect').empty();
                $('#UserSettingValueSelect').parent().hide();
                $('#UserSettingValue').parent().show();
            }
        }
    }
</script>
