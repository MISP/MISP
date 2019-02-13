<?php
    $table_data = array();
    $table_data[] = array('key' => __('Id'), 'value' => $role['Role']['id']);
    $table_data[] = array('key' => __('Name'), 'value' => $role['Role']['name']);
    $table_data[] = array('key' => __('Permission level'), 'value' => $premissionLevelName[$role['Role']['permission']]);
    foreach ($role['Role'] as $k => $item) {
        if (substr($k, 0, 5) === 'perm_' && !in_array($k, array('perm_add', 'perm_modify', 'perm_modify_org', 'perm_publish', 'perm_full'))) {
            $name = substr($k, 5);
            if (in_array($name, array('add', 'modify', 'modify_org', 'publish', 'full'))) {
                continue;
            }
            $table_data[] = array(
                'key' => Inflector::humanize(h($name)),
                'value_class' => $role['Role'][$k] ? 'green' : 'red',
                'value' => $role['Role'][$k] ? 'Granted' : 'Denied'
            );
        }

    }
    echo sprintf(
        '<div class="roles view row-fluid"><div class="span8" style="margin:0px;">%s</div></div>%s',
        sprintf(
            '<h2>%s</h2>%s',
            __('Role'),
            $this->element('genericElements/viewMetaTable', array('table_data' => $table_data))
        ),
        $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'roles'))
    );
?>
