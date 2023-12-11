<?php
/*
 *  echo $this->element('/genericElements/IndexTable/index_table', array(
 *      'top_bar' => (
 *          // search/filter bar information compliant with ListTopBar
 *      ),
 *      'data' => array(
            // the actual data to be used
 *      ),
 *      'fields' => array(
 *          // field list with information for the paginator
 *      ),
 *      'title' => optional title,
 *      'description' => optional description
 *  ));
 *
 */
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $data,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'active' => $context === 'me',
                                'url' => $baseurl . '/user_settings/index/user_id:me',
                                'text' => __('Me'),
                            ),
                            array(
                                'active' => $context === 'org',
                                'url' => $baseurl . '/user_settings/index/user_id:org',
                                'text' => __('Organisation'),
                                'requirement' => $isAdmin
                            ),
                            array(
                                'active' => $context === 'all',
                                'url' => $baseurl . '/user_settings/index/user_id:all',
                                'text' => __('All'),
                                'requirement' => $isSiteAdmin
                            )
                        )
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('Id'),
                    'sort' => 'id',
                    'class' => 'short',
                    'data_path' => 'UserSetting.id'
                ),
                array(
                    'name' => __('User'),
                    'sort' => 'User.email',
                    'class' => 'short',
                    'data_path' => 'User.email'
                ),
                array(
                    'name' => __('Setting'),
                    'class' => 'short',
                    'sort' => 'type',
                    'data_path' => 'UserSetting.setting'
                ),
                array(
                    'name' => __('Value'),
                    'sort' => 'type',
                    'element' => 'json',
                    'data_path' => 'UserSetting.value'
                ),
                array(
                    'name' => __('Restricted to'),
                    'sort' => 'type',
                    'data_path' => 'UserSetting.restricted'
                )
            ),
            'title' => __('User settings management'),
            'description' => __('Manage the individual user settings.'),
            'actions' => array(
                array(
                    'url' => '/user_settings/setSetting',
                    'url_params_data_paths' => array(
                        'UserSetting.user_id',
                        'UserSetting.setting'
                    ),
                    'icon' => 'edit'
                ),
                array(
                    'url' => '/user_settings/delete',
                    'url_params_data_paths' => array(
                        'UserSetting.id'
                    ),
                    'icon' => 'trash',
                    'postLink' => true,
                    'postLinkConfirm' => __('Are you sure you wish to delete this entry?')
                )
            )
        )
    ));
    echo '</div>';
    if ($context === 'me' || (!$isAdmin && !$isSiteAdmin)) {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'user_settings_index_me'));
    } else {
        echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'user_settings_index'));
    }
?>
