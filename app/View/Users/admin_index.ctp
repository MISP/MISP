<?php
    echo '<div class="index">';
    $description = __(
        'Click %s to reset the API keys of all sync and org admin users in one shot. This will also automatically inform them of their new API keys.',
        $this->Form->postLink(
            __('here'),
            $baseurl . '/users/resetAllSyncAuthKeys',
            array(
                'title' => __('Reset all sync user API keys'),
                'aria-label' => __('Reset all sync user API keys'),
                'class' => 'bold'
            ),
            __('Are you sure you wish to reset the API keys of all users with sync privileges?')
        )
    );
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $users,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'id' => 'create-button',
                                'title' => __('Modify filters'),
                                'fa-icon' => 'search',
                                'onClick' => 'getPopup',
                                'onClickParams' => array($urlparams, 'admin/users', 'filterUserIndex')
                            )
                        )
                    ),
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value'
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('Id'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'User.id'
                ),
                array(
                    'name' => __('Org'),
                    'sort' => 'User.org_id',
                    'element' => 'org',
                    'data_path' => 'Organisation'
                ),
                array(
                    'name' => __('Role'),
                    'sort' => 'User.role_id',
                    'class' => 'short',
                    'element' => 'role',
                    'data_path' => 'Role'
                ),
                array(
                    'name' => __('Email'),
                    'sort' => 'User.email',
                    'data_path' => 'User.email'
                ),
                array(
                    'name' => __('authkey'),
                    'sort' => 'User.authkey',
                    'class' => 'bold quickSelect',
                    'data_path' => 'User.authkey',
                    'onClick' => 'quickSelect(this);'
                ),
                array(
                    'name' => __('Autoalert'),
                    'element' => 'boolean',
                    'sort' => 'User.autoalert',
                    'class' => 'short',
                    'data_path' => 'User.autoalert'
                ),
                array(
                    'name' => __('Contactalert'),
                    'element' => 'boolean',
                    'sort' => 'User.contactalert',
                    'class' => 'short',
                    'data_path' => 'User.contactalert'
                ),
                array(
                    'name' => __('PGP Key'),
                    'element' => 'boolean',
                    'sort' => 'User.gpgkey',
                    'class' => 'short',
                    'data_path' => 'User.gpgkey'
                ),
                array(
                    'name' => __('SMIME'),
                    'element' => 'boolean',
                    'sort' => 'User.certif_public',
                    'class' => 'short',
                    'data_path' => 'User.certif_public',
                    'requirement' => Configure::read('SMIME.enabled')
                ),
                array(
                    'name' => __('NIDS SID'),
                    'sort' => 'User.nids_sid',
                    'class' => 'short',
                    'data_path' => 'User.nids_sid'
                ),
                array(
                    'name' => __('Terms Accepted'),
                    'element' => 'boolean',
                    'sort' => 'User.termsaccepted',
                    'class' => 'short',
                    'data_path' => 'User.termsaccepted'
                ),
                array(
                    'name' => __('Last Login'),
                    'sort' => 'User.current_login',
                    'element' => 'datetime',
                    'class' => 'short',
                    'data_path' => 'User.current_login'
                ),
                array(
                    'name' => __('Created'),
                    'sort' => 'User.date_created',
                    'element' => 'datetime',
                    'class' => 'short',
                    'data_path' => 'User.date_created'
                ),
                array(
                    'name' => (Configure::read('Plugin.CustomAuth_name') ? Configure::read('Plugin.CustomAuth_name') : __('External Auth')),
                    'sort' => 'User.external_auth_required',
                    'element' => 'boolean',
                    'class' => 'short',
                    'data_path' => 'User.external_auth_required',
                    'requirement' => (Configure::read('Plugin.CustomAuth_enable') && empty(Configure::read('Plugin.CustomAuth_required')))
                ),
                array(
                    'name' => __('Monitored'),
                    'element' => 'toggle',
                    'url' => '/admin/users/monitor',
                    'url_params_data_paths' => array(
                        'User.id'
                    ),
                    'sort' => 'User.disabled',
                    'class' => 'short',
                    'data_path' => 'User.monitored',
                    'requirement' => (
                        Configure::read('Security.user_monitoring_enabled') &&
                        $isSiteAdmin
                    )
                ),
                array(
                    'name' => __('Disabled'),
                    'element' => 'boolean',
                    'sort' => 'User.disabled',
                    'class' => 'short',
                    'data_path' => 'User.disabled'
                )
            ),
            'title' => __('Users index'),
            'html' => $description,
            'actions' => array(
                array(
                    'icon' => 'sync',
                    'onclick' => 'initiatePasswordReset(\'[onclick_params_data_path]\');',
                    'onclick_params_data_path' => 'User.id',
                    'title' => __('Create new credentials and inform user'),
                    'complex_requirement' => array(
                        'options' => array(
                            'datapath' => array('User.org_id'),
                            'me' => $me,
                            'isSiteAdmin' => $isSiteAdmin
                        ),
                        'function' => function($row, $options)
                        {
                            return (
                                (
                                    $options['me']['Role']['perm_admin'] &&
                                    ($row['User']['org_id'] == $options['me']['org_id'])
                                ) ||
                                $options['isSiteAdmin']
                            );
                        }
                    )
                ),
                array(
                    'url' => '/admin/users/edit',
                    'url_params_data_paths' => array(
                        'User.id'
                    ),
                    'icon' => 'edit'
                ),
                array(
                    'url' => '/admin/users/delete',
                    'url_params_data_paths' => array(
                        'User.id'
                    ),
                    'postLink' => 1,
                    'postLinkConfirm' => __('Are you sure you want to delete the user? It is highly recommended to never delete users but to disable them instead.'),
                    'icon' => 'trash'
                ),
                array(
                    'url' => '/admin/users/view',
                    'url_params_data_paths' => array(
                        'User.id'
                    ),
                    'icon' => 'eye'
                )
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'indexUser'));
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    if (passedArgsArray['context'] === undefined) {
        passedArgsArray['context'] = 'pending';
    }
    $(document).ready(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter('/context:' + passedArgsArray['context']);
        });
        $('#quickFilterField').on('keypress', function (e) {
            if(e.which === 13) {
                runIndexQuickFilter('/context:' + passedArgsArray['context']);
            }
        });
    });
</script>
