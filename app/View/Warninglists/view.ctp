<?php
    $data = $warninglist['Warninglist'];
    $types = array_column($warninglist['WarninglistType'], 'type');
    $table_data = array(
        array('key' => __('ID'), 'value' => $data['id']),
        array('key' => __('Name'), 'value' => $data['name']),
        array('key' => __('Description'), 'value' => $data['description']),
        array('key' => __('Version'), 'value' => $data['version']),
        array('key' => __('Type'), 'value' => $data['type']),
        array('key' => __('Accepted attribute types'), 'value' => implode(', ', $types)),
        array(
            'key' => __('Enabled'),
            'boolean' => $data['enabled'],
            'html' => sprintf(
                ' (<a href="%s/warninglists/enableWarninglist/%s%s" title="%s">%s</a>)',
                $baseurl,
                h($warninglist['Warninglist']['id']),
                $data['enabled'] ? '' : '/1',
                $data['enabled'] ? __('Disable') : __('Enable'),
                $data['enabled'] ? __('disable') : __('enable')
            )
        ),
    );
    echo sprintf(
        '<div class="warninglist view"><div class="row-fluid"><div class="span8" style="margin:0;">%s</div></div><h4>%s</h4>%s</div>',
        sprintf(
            '<h2>%s</h2>%s',
            h(strtoupper($warninglist['Warninglist']['name'])),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        __('Values'),
        implode('<br>', array_column($warninglist['WarninglistEntry'], 'value'))
    );
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'warninglist', 'menuItem' => 'view'));

