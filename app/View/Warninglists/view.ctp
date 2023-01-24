<?php
    $data = $warninglist['Warninglist'];
    $types = implode(', ', array_column($warninglist['WarninglistType'], 'type'));
    $table_data = array(
        array('key' => __('ID'), 'value' => $data['id']),
        array('key' => __('Name'), 'value' => $data['name']),
        array('key' => __('Description'), 'value' => $data['description']),
        array('key' => __('Version'), 'value' => $data['version']),
        array('key' => __('Category'), 'value' => $possibleCategories[$data['category']]),
        array('key' => __('Type'), 'value' => $data['type']),
        array('key' => __('Accepted attribute types'), 'value' => $types),
        array(
            'key' => __('Enabled'),
            'boolean' => $data['enabled'],
            'html' => $me['Role']['perm_warninglist'] ? sprintf(
                ' <a href="%s/warninglists/enableWarninglist/%s%s" title="%s">%s</a>',
                $baseurl,
                h($warninglist['Warninglist']['id']),
                $data['enabled'] ? '' : '/1',
                $data['enabled'] ? __('Disable') : __('Enable'),
                $data['enabled'] ? __('Disable') : __('Enable')
            ): '',
        ),
    );

    $values = [];
    foreach ($warninglist['WarninglistEntry'] as $entry) {
        $value = '<span class="warninglist-value">'. h($entry['value']) . '</span>';
        if ($entry['comment']) {
            $value .= ' <span class="warninglist-comment"># ' . h($entry['comment']) . '</span>';
        }
        $values[] = $value;
    }

    echo '<div class="warninglist view">';
    echo sprintf(
        '<div class="row-fluid"><div class="span8" style="margin:0;">%s</div></div><h4>%s</h4>',
        sprintf(
            '<h2>%s</h2>%s',
            h($warninglist['Warninglist']['name']),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        __('Values')
    );
    echo implode('<br>', $values);
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', [
        'menuList' => 'warninglist',
        'menuItem' => 'view',
        'id' => $data['id'],
        'isDefault' => $data['default'] == 1,
    ]);
