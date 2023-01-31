<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class InboxNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute('Inbox', 'index', $this->bcf->defaultCRUD('Inbox', 'index'));
        $this->bcf->addRoute('Inbox', 'view', $this->bcf->defaultCRUD('Inbox', 'view'));
        $this->bcf->addRoute('Inbox', 'discard', [
            'label' => __('Discard request'),
            'icon' => 'trash',
            'url' => '/inbox/discard/{{id}}',
            'url_vars' => ['id' => 'id'],
        ]);
        $this->bcf->addRoute('Inbox', 'process', [
            'label' => __('Process request'),
            'icon' => 'cogs',
            'url' => '/inbox/process/{{id}}',
            'url_vars' => ['id' => 'id'],
        ]);
    }
    
    public function addParents()
    {
        $this->bcf->addParent('Inbox', 'view', 'Inbox', 'index');
        $this->bcf->addParent('Inbox', 'discard', 'Inbox', 'index');
        $this->bcf->addParent('Inbox', 'process', 'Inbox', 'index');
    }
    
    public function addLinks()
    {
        $this->bcf->addSelfLink('Inbox', 'view');
    }
    
    public function addActions()
    {
        $this->bcf->addAction('Inbox', 'view', 'Inbox', 'process');
        $this->bcf->addAction('Inbox', 'view', 'Inbox', 'discard');

    }
}
