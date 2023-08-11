<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class NoticelistsNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute('Noticelists', 'update', [
            'label' => __('Update Noticelists'),
            'url' => '/noticelists/update',
            'icon' => 'circle-up',
            'isPOST' => true,
        ]);
    }

    public function addActions()
    {
        $this->bcf->addAction('Noticelists', 'index', 'Noticelists', 'update');
    }
}
