<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class InstanceNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute('Instance', 'home', [
            'label' => __('Home'),
            'url' => '/',
            'icon' => 'home'
        ]);
        $this->bcf->addRoute('Instance', 'settings', [
            'label' => __('Settings'),
            'url' => '/instance/settings',
            'icon' => 'cogs'
        ]);
        $this->bcf->addRoute('Instance', 'migrationIndex', [
            'label' => __('Database Migration'),
            'url' => '/instance/migrationIndex',
            'icon' => 'database'
        ]);
    }
}
