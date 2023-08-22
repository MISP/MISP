<?php
namespace App\Controller\Component\Navigation;

class InstanceNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute(
            'Instance',
            'home',
            [
            'label' => __('Home'),
            'url' => '/',
            'icon' => 'home'
            ]
        );
        $this->bcf->addRoute(
            'Instance',
            'settings',
            [
            'label' => __('Settings'),
            'url' => '/instance/settings',
            'icon' => 'cogs'
            ]
        );
        $this->bcf->addRoute(
            'Instance',
            'migrationIndex',
            [
            'label' => __('Database Migration'),
            'url' => '/instance/migrationIndex',
            'icon' => 'database'
            ]
        );
    }
}
