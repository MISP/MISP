<?php
namespace App\Controller\Component\Navigation;

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
