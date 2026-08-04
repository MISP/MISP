<?php
    echo $this->element('generic_table', array(
        'items' => $list,
        'alias' => __('Tag Collections'),
        'controller' => 'tag_collections',
        'headers' => array(
            'id' => array('sort' => 1, 'alias' => __('ID')),
            'uuid' => array('sort' => 1, 'alias' => __('UUID')),
            'name' => array('sort' => 1),
            'tags' => array('alias' => __('Tags')),
            'galaxies' => array('alias' => __('Galaxies')),
            'all_orgs' => array('alias' => __('All orgs')),
            'org_id' => array('alias' => __('Organisation')),
            'user_id' => array('alias' => __('User')),
            'description' => array('alias' => __('Description')),
            'Actions' => array('alias' => __('Actions'))
        ),
        'row_path' => 'TagCollections/index_row'
    ));

    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'tag-collections', 'menuItem' => 'index'));

