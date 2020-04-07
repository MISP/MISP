<?php
    $suggestedOrgText = __('No preference');
    $suggestedRoleText = '';
    if ($suggestedOrg !== null) {
        if ($suggestedOrg === false) {
            $suggestedOrgText = '<br />&nbsp;&nbsp;<span class="bold red">' . __('Conflicting requirements') . '</span>';
        } else if ($suggestedOrg === -1){
            $suggestedOrgText = sprintf(
                '<span class="red">%s%s</span>%s <a href="%s/admin/organisations/add%s%s" class="black fas fa-plus"></a>',
                empty($registration['Inbox']['data']['org_name']) ? '' : h($registration['Inbox']['data']['org_name']) . ' ',
                empty($registration['Inbox']['data']['org_uuid']) ? '' : h($registration['Inbox']['data']['org_uuid']) . ' ',
                __('Requested organisation not found.'),
                $baseurl,
                empty($registration['Inbox']['data']['org_name']) ? '' : '/name:' . h($registration['Inbox']['data']['org_name']),
                empty($registration['Inbox']['data']['org_uuid']) ? '' : '/uuid:' . h($registration['Inbox']['data']['org_uuid'])
            );
        } else {
            $suggestedOrgText = sprintf(
                '<span class="bold %s">(%s)%s</span>%s',
                $suggestedOrg[2] ? 'green' : 'orange',
                h($suggestedOrg[0]),
                h($suggestedOrg[1]),
                $suggestedOrg[2] ? '' : ' - <span class="red bold">' . __('known remote organisation, will be converted to local') . '</span>'
            );
        }
    }
    if ($suggestedRole !== null) {
        if ($suggestedRole === false) {
            $suggestedRoleText = '<br />&nbsp;&nbsp;<span class="bold red">' . __('Conflicting requirements') . '</span>';
        } else {
            foreach ($suggestedRole as $perm_flag => $perm_flag_value) {
                $perm_flag_name = substr($perm_flag, 5);
                if ($perm_flag_value) {
                    $suggestedRoleText .= sprintf(
                        '<br />&nbsp;&nbsp;<span class="perm-requirements bold" data-perm="%s" data-value="%s">%s</span> ',
                        h($perm_flag_name),
                        $perm_flag_value ? '1' : '0',
                        h($perm_flag_name)
                    );
                }
            }
        }
    } else {
        $suggestedRoleText = '<br />&nbsp;&nbsp;<span class="bold red">' . __('No preference') . '</span>';
    }
    $description = __(
        "The requested details were as follows\n\nOrganisation:\n&nbsp;&nbsp;%s\nRole: %s\n\n",
        $suggestedOrgText,
        $suggestedRoleText
    );
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'title' => __('Accept registrations'),
            'description' => nl2br($description),
            'model' => 'User',
            'fields' => array(
                array(
                    'field' => 'org_id',
                    'label' => __('Organisation'),
                    'class' => 'input-xxlarge',
                    'required' => 1,
                    'options' => $orgs,
                    'default' => empty($suggestedOrg[0]) ? false : $suggestedOrg[0]
                ),
                array(
                    'field' => 'role_id',
                    'label' => __('Role'),
                    'class' => 'input-xxlarge',
                    'required' => 1,
                    'options' => $roles
                )
            ),
            'submit' => array(
                'ajaxSubmit' => sprintf(
                    'submitPopoverForm(%s, %s, 0, 1)',
                    "'acceptUserRegistrations'",
                    "' . $id . '"
                )
            )
        )
    ));
?>
</div>
<script type="text/javascript">
    var role_perms = <?= json_encode($role_perms) ?>;
    function checkPermConditions() {
        var selectedRole = $('#UserRoleId').val();
        var selectedRoleDetails = role_perms[selectedRole];
        $.each($('.perm-requirements'), function() {
            if (selectedRoleDetails["perm_" + $(this).data('perm')] != $(this).data('value')) {
                $(this).removeClass('green');
                $(this).addClass('red');
            } else {
                $(this).removeClass('red');
                $(this).addClass('green');
            }
        });
    }
    $(document).ready(function() {
        checkPermConditions();
        $('#UserRoleId').on('change', function() {
            checkPermConditions();
        });
    });
</script>
