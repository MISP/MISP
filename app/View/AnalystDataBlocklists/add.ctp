<?php
    $fieldDesc = array();
    $fieldDesc['uuids'] = __('Enter a single or a list of UUIDs');
    $fieldDesc['analyst_data_orgc'] = __('(Optional) The organisation that the event is associated with');
    $fieldDesc['analyst_data_info'] = __('(Optional) The analyst data value that you would like to block');
    $fieldDesc['comment'] = __('(Optional) Any comments you would like to add regarding this (or these) entries');
    echo $this->element('genericElements/Form/genericForm', array(
        'form' => $this->Form,
        'data' => array(
            'model' => 'AnalystDataBlocklist',
            'title' => $action == 'add' ? __('Add block entry for Analyst Data') : __('Edit block entry for Analyst Data'),
            'fields' => array(
                array(
                    'disabled' => $action != 'add' ? 'disabled' : '',
                    'field' => 'uuids',
                    'class' => 'span6',
                    'label' => __('Analyst Data UUID'),
                    'type' => 'textarea',
                    'default' => isset($blockEntry['AnalystDataBlocklist']['analyst_data_uuid']) ? $blockEntry['AnalystDataBlocklist']['analyst_data_uuid'] : '',
                ),
                array(
                    'field' => 'analyst_data_orgc',
                    'label' => __('Creating organisation'),
                    'class' => 'span6',
                    'type' => 'text',
                    'default' => isset($blockEntry['AnalystDataBlocklist']['analyst_data_orgc']) ? $blockEntry['AnalystDataBlocklist']['analyst_data_orgc'] : ''
                ),
                array(
                    'field' => 'analyst_data_info',
                    'label' => __('Analyst Data value'),
                    'class' => 'span6',
                    'type' => 'text',
                    'default' => isset($blockEntry['AnalystDataBlocklist']['analyst_data_info']) ? $blockEntry['AnalystDataBlocklist']['analyst_data_info'] : ''
                ),
                array(
                    'field' => 'comment',
                    'label' => __('Comment'),
                    'class' => 'span6',
                    'type' => 'text',
                    'default' => isset($blockEntry['AnalystDataBlocklist']['comment']) ? $blockEntry['AnalystDataBlocklist']['comment'] : ''
                ),
            ),
            'submit' => array(
                'ajaxSubmit' => ''
            )
        ),
        'fieldDesc' => $fieldDesc
    ));
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'analyst_data', 'menuItem' => 'index_blocklist'));
?>

<?php echo $this->Js->writeBuffer(); // Write cached scripts
