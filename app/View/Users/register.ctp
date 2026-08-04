<?php
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'description' => nl2br(h($message)),
            'title' => __('Register for a new user account'),
            'model' => 'User',
            'skip_side_menu' => 1,
            'fields' => array(
                array(
                    'field' => 'email',
                    'label' => __('Your email address'),
                    'class' => 'input-xxlarge',
                    'required' => 1
                ),
                array(
                    'field' => 'org_name',
                    'label' => __('Your organisation\'s name (optional)'),
                    'class' => 'input-xxlarge'
                ),
                array(
                    'field' => 'org_uuid',
                    'label' => __('Your MISP org uuid (optional)'),
                    'class' => 'input-xxlarge'
                ),
                array(
                    'field' => 'custom_perms',
                    'type' => 'checkbox',
                    'label' => __("Request custom role")
                ),
                array(
                    'field' => 'perm_publish',
                    'type' => 'checkbox',
                    'label' => __("Publish permission"),
                    'class' => 'role-field',
                    'hidden' => 1
                ),
                array(
                    'field' => 'perm_admin',
                    'type' => 'checkbox',
                    'label' => __("Org admin permission"),
                    'class' => 'role-field',
                    'hidden' => 1
                ),
                array(
                    'field' => 'perm_sync',
                    'type' => 'checkbox',
                    'class' => 'role-field',
                    'label' => __("Sync permission"),
                    'hidden' => 1
                ),
                array(
                    'field' => 'pgp',
                    'label' => __('PGP key (optional)'),
                    'class' => 'input-xxlarge',
                    'type' => 'textarea'
                ),
                array(
                    'field' => 'message',
                    'label' => __('Message to the admins'),
                    'class' => 'input-xxlarge',
                    'type' => 'textarea'
                )
            ),
            'submit' => array(
                'action' => $this->request->params['action']
            )
        )
    ));
?>
</div>
<script type="text/javascript">
    $(document).ready(function() {
        $('#UserCustomPerms').change(function() {
            if ($('#UserCustomPerms').prop("checked") != true) {
                $('.role-field').prop("checked", false)
            }
            $('.role-field').parent().parent().toggleClass('hidden');
        });
    });
</script>
