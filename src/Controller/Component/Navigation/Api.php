<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class ApiNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute('Api', 'index', [
            'label' => __('API'),
            'url' => '/api/index',
            'icon' => 'code'
        ]);
    }
}
