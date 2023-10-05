<?php
namespace App\Controller\Component\Navigation;

class SharingGroupsNavigation extends BaseNavigation
{

    public function addLinks()
    {
        $this->bcf->addCustomLink(
            'SharingGroups',
            'index',
            '/sharing-group-blueprints',
            __('List Sharing Group Blueprints'),
            [
            'icon' => 'ruler',
            ]
        );
    }

}
