<?php
namespace App\Controller\Component\Navigation;

class ApiNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute(
            'Api',
            'index',
            [
            'label' => __('API'),
            'url' => '/api/index',
            'icon' => 'code'
            ]
        );
    }
}
