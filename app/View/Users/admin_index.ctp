<?php
    if (!$this->request->is('ajax')) {
        // Allow reset Keys, filtering and searching if viewing the /users/index page
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
        $topBar = array(
            'children' => array(
                array(
                    'children' => array(
                        array(
                            'class' => 'hidden mass-select',
                            'text' => __('Disable selected users'),
                            'onClick' => "multiSelectToggleField",
                            'onClickParams' => array('admin/users', 'massToggleField', 'disabled', '1', '#UserUserIds')
                        ),
                        array(
                            'class' => 'hidden mass-select',
                            'text' => __('Enable selected users'),
                            'onClick' => "multiSelectToggleField",
                            'onClickParams' => array('admin/users', 'massToggleField', 'disabled', '0', '#UserUserIds')
                        ),
                        array(
                            'class' => 'hidden mass-select',
                            'text' => __('Disable publish emailing'),
                            'onClick' => "multiSelectToggleField",
                            'onClickParams' => array('admin/users', 'massToggleField', 'autoalert', '0', '#UserUserIds')
                        ),
                        array(
                            'class' => 'hidden mass-select',
                            'text' => __('Enable publish emailing'),
                            'onClick' => "multiSelectToggleField",
                            'onClickParams' => array('admin/users', 'massToggleField', 'autoalert', '1', '#UserUserIds')
                        ),
                    )
                ),
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
                    'type' => 'simple',
                    'children' => array(
                        array(
                            'url' => $baseurl . '/admin/users/index',
                            'text' => __('All'),
                            'active' => !isset($passedArgsArray['disabled']) && !isset($passedArgsArray['inactive']),
                        ),
                        array(
                            'url' => $baseurl . '/admin/users/index/searchdisabled:0',
                            'text' => __('Enabled'),
                            'active' => isset($passedArgsArray['disabled']) && $passedArgsArray['disabled'] === "0",
                        ),
                        array(
                            'url' => $baseurl . '/admin/users/index/searchdisabled:1',
                            'text' => __('Disabled'),
                            'active' => isset($passedArgsArray['disabled']) && $passedArgsArray['disabled'] === "1",
                        ),
                        array(
                            'url' => $baseurl . '/admin/users/index/searchinactive:1',
                            'text' => __('Inactive'),
                            'active' => isset($passedArgsArray['inactive']) && $passedArgsArray['inactive'] === "1",
                        )
                    )
                ),
                array(
                    'type' => 'search',
                    'button' => __('Filter'),
                    'placeholder' => __('Enter value to search'),
                    'searchKey' => 'value',
                )
            )
        );
        $multiSelectField = array(array(
            'element' => 'selector',
            'class' => 'short',
            'data' => array(
                'id' => array(
                    'value_path' => 'User.id'
                )
            )
        ));
    } else {
        $description = '';
        $topBar = [];
        $multiSelectField = array();
    }
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $users,
            'top_bar' => $topBar,
            'fields' => array_merge(
                $multiSelectField,
                array(
                    array(
                        'name' => __('ID'),
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
                        'name' => __('Authkey'),
                        'sort' => 'User.authkey',
                        'class' => 'bold quickSelect',
                        'data_path' => 'User.authkey',
                        'privacy' => 1,
                        'requirement' => empty(Configure::read('Security.advanced_authkeys'))
                    ),
                    array(
                        'name' => '',
                        'header_title' => __('TOTP'),
                        'icon' => 'mobile',
                        'element' => 'boolean',
                        'sort' => 'User.totp',
                        'class' => 'short',
                        'data_path' => 'User.totp',
                        'colors' => true,
                        'requirement' => empty(Configure::read('Security.otp_disabled')),
                    ),
                    array(
                        'name' => '',
                        'header_title' => __('Contact alert'),
                        'icon' => 'handshake',
                        'element' => 'boolean',
                        'sort' => 'User.contactalert',
                        'class' => 'short',
                        'data_path' => 'User.contactalert',
                        'colors' => true,
                    ),
                    array(
                        'name' => '',
                        'header_title' => __('Notification'),
                        'icon' => 'clock',
                        'element' => 'custom',
                        'class' => 'short',
                        'function' => function (array $user) use ($periodic_notifications) {
                            $subscriptions = [];
                            if ($user['User']['autoalert']) {
                                $subscriptions[] = 'e';
                            }
                            foreach ($periodic_notifications as $period) {
                                if (!empty($user['User'][$period])) {
                                    $subscriptions[] = substr($period, 13, 1);
                                }
                            }
                            return implode('/', $subscriptions);
                        }
                    ),
                    array(
                        'name' => '',
                        'header_title' => __('PGP public key'),
                        'icon' => 'key',
                        'element' => 'boolean',
                        'sort' => 'User.gpgkey',
                        'class' => 'short',
                        'data_path' => 'User.gpgkey',
                        'colors' => true,
                    ),
                    array(
                        'name' => '',
                        'header_title' => __('S/MIME public key'),
                        'icon' => 'lock',
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
                        'name' => '',
                        'header_title' => __('Terms accepted'),
                        'icon' => 'gavel',
                        'element' => 'boolean',
                        'sort' => 'User.termsaccepted',
                        'class' => 'short',
                        'data_path' => 'User.termsaccepted',
                        'colors' => true,
                    ),
                    array(
                        'name' => __('Last Login'),
                        'sort' => 'User.current_login',
                        'element' => 'datetime',
                        'empty' => __('Never'),
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
                        'name' => __('Last API Access'),
                        'sort' => 'User.last_api_access',
                        'element' => 'datetime',
                        'class' => 'short',
                        'data_path' => 'User.last_api_access',
                    ),
                    array(
                        'name' => (Configure::read('Plugin.CustomAuth_name') ? Configure::read('Plugin.CustomAuth_name') : __('External Auth')),
                        'sort' => 'User.external_auth_required',
                        'element' => 'boolean',
                        'class' => 'short',
                        'data_path' => 'User.external_auth_required',
                        'requirement' => Configure::read('Plugin.CustomAuth_enable') && empty(Configure::read('Plugin.CustomAuth_required'))
                    ),
                    array(
                        'name' => '',
                        'header_title' => __('Monitored'),
                        'icon' => 'desktop',
                        'element' => 'toggle',
                        'url' => $baseurl . '/admin/users/monitor',
                        'url_params_data_paths' => array(
                            'User.id'
                        ),
                        'sort' => 'User.monitored',
                        'class' => 'short',
                        'data_path' => 'User.monitored',
                        'requirement' => $isSiteAdmin && Configure::read('Security.user_monitoring_enabled')
                    ),
                    array(
                        'name' => '',
                        'header_title' => __('User disabled'),
                        'icon' => 'times',
                        'element' => 'boolean',
                        'sort' => 'User.disabled',
                        'class' => 'short',
                        'data_path' => 'User.disabled',
                        'colors' => true,
                    )
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
                        'function' => function($row) use ($me, $isSiteAdmin)
                        {
                            return (
                                (
                                    $me['Role']['perm_admin'] &&
                                    ($row['User']['org_id'] == $me['org_id'])
                                ) ||
                                $isSiteAdmin
                            );
                        }
                    )
                ),
                array(
                    'url' => $baseurl . '/admin/users/edit',
                    'url_params_data_paths' => array(
                        'User.id'
                    ),
                    'icon' => 'edit',
                    'title' => __('Edit')
                ),
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/admin/users/destroy/[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'User.id',
                    'icon' => 'bomb',
                    'title' => __('Destroy sessions')
                ],
                [
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/admin/users/delete/[onclick_params_data_path]\');',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'User.id',
                    'icon' => 'trash',
                    'title' => __('Delete')
                ],
                array(
                    'url' => $baseurl . '/admin/users/view',
                    'url_params_data_paths' => array(
                        'User.id'
                    ),
                    'icon' => 'eye',
                    'title' => __('View'),
                    'dbclickAction' => true,
                )
            )
        )
    ));
    if (!$this->request->is('ajax')) {
        echo '</div>';
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'indexUser'));
    }
