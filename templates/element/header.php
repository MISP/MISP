<?php
    $menu = array(
        'home' => array(
            'url' => '#',
            'class' => 'navbar-brand',
            'text' => 'Cerebrate'
        ),
        'menu' => $menu
    );
    echo $this->element('genericElements/header_scaffold', ['data' => $menu]);
