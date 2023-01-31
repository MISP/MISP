<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class BroodsNavigation extends BaseNavigation
{
    public function addLinks()
    {
        $this->bcf->addLink('Broods', 'view', 'LocalTools', 'broodTools');
        $this->bcf->addLink('Broods', 'edit', 'LocalTools', 'broodTools');
    }
}
