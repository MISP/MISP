<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $data,
            'top_bar' => array(
                'children' => array(
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
                    'data_path' => 'Inbox.id',
                ),
                array(
                    'name' => __('Type'),
                    'sort' => 'type',
                    'class' => 'short',
                    'data_path' => 'Inbox.type',
                ),
                array(
                    'name' => __('Title'),
                    'sort' => 'Inbox.title',
                    'data_path' => 'Inbox.title',
                ),
                array(
                    'name' => __('Comment'),
                    'data_path' => 'Inbox.comment',
                )
            ),
            'title' => __('Instance inbox'),
            'description' => __('You can find messages sent to this instance in the following list. Type denotes the type of request (such as registration). View each entry to see more details about the request\'s contents.'),
            'actions' => array(
                array(
                    'url' => '/inbox/view',
                    'url_params_data_paths' => array(
                        'Inbox.uuid'
                    ),
                    'icon' => 'eye'
                ),
                array(
                    'url' => '/inbox/delete',
                    'url_params_data_paths' => array(
                        'Inbox.uuid'
                    ),
                    'postLink' => 1,
                    'postLinkConfirm' => __('Are you sure you want to delete the message from the inbox?'),
                    'icon' => 'trash'
                )
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'administration', 'menuItem' => 'inbox'));
?>
