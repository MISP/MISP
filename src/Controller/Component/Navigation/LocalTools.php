<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class LocalToolsNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute('LocalTools', 'viewConnector', [
            'label' => __('View'),
            'textGetter' => 'connector',
            'url' => '/localTools/viewConnector/{{connector}}',
            'url_vars' => ['connector' => 'connector'],
        ]);
        $this->bcf->addRoute('LocalTools', 'broodTools', [
            'label' => __('Brood Tools'),
            'url' => '/localTools/broodTools/{{id}}',
            'url_vars' => ['id' => 'id'],
        ]);
    }
    
    public function addParents()
    {
        $this->bcf->addParent('LocalTools', 'viewConnector', 'LocalTools', 'index');
    }
    
    public function addLinks()
    {
        $passedData = $this->request->getParam('pass');
        if (!empty($passedData[0])) {
            $brood_id = $passedData[0];
            $this->bcf->addParent('LocalTools', 'broodTools', 'Broods', 'view', [
                'textGetter' => [
                    'path' => 'name',
                    'varname' => 'broodEntity',
                ],
                'url' => "/broods/view/{$brood_id}",
            ]);
            $this->bcf->addLink('LocalTools', 'broodTools', 'Broods', 'view', [
                'url' => "/broods/view/{$brood_id}",
            ]);
            $this->bcf->addLink('LocalTools', 'broodTools', 'Broods', 'edit', [
                'url' => "/broods/view/{$brood_id}",
            ]);
        }
        $this->bcf->addSelfLink('LocalTools', 'broodTools');
    }
}
