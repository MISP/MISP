<?php
echo sprintf('<div%s>', !$this->request->is('ajax') ? ' class="index"' : '');
echo $this->element('/genericElements/IndexTable/index_table', array(
    'data' => array(
        'light_paginator' => 1,
        'data' => $data,
          'fields' => [
            [
                'name' => __('Status'),
                'data_path' => 'status'
            ],
            [
                'name' => __('Platform'),
                'data_path' => 'platform'
            ],
            [
                'name' => __('Region'),
                'data_path' => 'region'
            ],
            [
                'name' => __('Browser'),
                'data_path' => 'browser'
            ],
            [
                'name' => __('Language'),
                'data_path' => 'accept_lang'
            ],
            [
                'name' => __('IP'),
                'data_path' => 'ip'
            ],
                        [
                'name' => __('First Seen'),
                'data_path' => 'first_seen'
            ],
            [
                'name' => __('Last Seen'),
                'data_path' => 'last_seen'
            ],
            [
                'name' => __('Login actions'),
                'data_path' => 'actions'
            ]
        ],
        'actions' => array(
             array(
                'title' => __('Trust'),
                'url' => $baseurl . '/userLoginProfiles/trust',
                'url_params_data_paths' => array(
                    'id',
                ),
                'postLink' => true,
                'postLinkConfirm' => __('Are you sure you want to mark this connection as trusted?'),
                'icon' => 'shield-alt',
                'complex_requirement' => function ($object) {
                    return 'unknown' == $object['status'] || mb_strpos($object['status'], 'likely') !== false;
                }
            ),
            array(
                'title' => __('Malicious'),
                'url' => $baseurl . '/userLoginProfiles/malicious',
                'url_params_data_paths' => array(
                    'id'
                ),
                'postLink' => true,
                'postLinkConfirm' => __('Was this connection suspicious or malicious?'),
                'icon' => 'bug',
                'complex_requirement' => function ($object) { 
                    return 'unknown' == $object['status'] || mb_strpos($object['status'], 'likely') !== false;
                }
            ),
        ),
        'title' => __('Recent login attempts'),
        'description' => 'Below are your most recent logins, please review and confirm it was you. This information is used to alert you when we detect suspcicious logins.',
        'pull' => 'right'
        
    )
));
echo '</div>';

if (!$this->request->is('ajax')) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view'));

}
