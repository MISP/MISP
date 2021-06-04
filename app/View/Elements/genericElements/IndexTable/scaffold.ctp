<?php
    $randomId = bin2hex(openssl_random_pseudo_bytes(8));
    echo sprintf(
        '<div id="%s" %s>',
        empty($scaffold_data['containerId']) ? ('index_container_' . $randomId . '_content') : $scaffold_data['containerId'] . '_content',
        (empty($ajax) ? 'class="index"' : '')
    );
    echo $this->element('genericElements/IndexTable/index_table', $scaffold_data);
    echo '</div>';
    if (empty($ajax)) {
        echo $this->element('/genericElements/SideMenu/side_menu', $menuData);
    }
?>
