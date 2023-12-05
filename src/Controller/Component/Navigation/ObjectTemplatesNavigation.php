<?php
namespace App\Controller\Component\Navigation;

class ObjectTemplatesNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute('ObjectTemplates', 'update', [
            'label' => __('Update ObjectTemplates'),
            'url' => '/object-templates/update',
            'icon' => 'circle-up',
            'isPOST' => true,
        ]);
    }

    public function addActions()
    {
        $this->bcf->addAction('ObjectTemplates', 'index', 'ObjectTemplates', 'update');
    }
}
