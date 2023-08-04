<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class SharingGroupsNavigation extends BaseNavigation
{

    public function addLinks()
    {
        $this->bcf->addCustomLink('SharingGroups', 'index', '/sharing-group-blueprints', __('List Sharing Group Blueprints'), [
            'icon' => 'ruler',
        ]);
    }

}
