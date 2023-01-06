<?php
echo sprintf('<div%s>', !$this->request->is('ajax') ? ' class="index"' : '');
echo $this->element('/genericElements/IndexTable/index_table', array(
    'data' => array(
        'light_paginator' => 1,
        'data' => $data,
        // 'top_bar' => [
        //     'pull' => 'right',
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
                'name' => __('Last Seen'),
                'data_path' => 'last_seen'
            ],
            [
                'name' => __('First Seen'),
                'data_path' => 'first_seen'
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
            ),
            array(
                'title' => __('Malicious'),
                'url' => $baseurl . '/userLoginProfiles/malicious',
                'url_params_data_paths' => array(
                    'id'
                ),
                'postLink' => true,
                'postLinkConfirm' => __('Was this connection suspicious or malicious?'),
                'icon' => 'trash',
            ),
        ),
        'title' => __('Recent login attempts'),
        'description' => 'TODO description - the list below allows you to ...',
        'pull' => 'right'
        
    )
));
echo '</div>';

if (!$this->request->is('ajax')) {
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'globalActions', 'menuItem' => 'view'));

}
