<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class OutboxNavigation extends BaseNavigation
{
    function addRoutes()
    {
        $this->bcf->addRoute('Outbox', 'index', $this->bcf->defaultCRUD('Outbox', 'index'));
        $this->bcf->addRoute('Outbox', 'view', $this->bcf->defaultCRUD('Outbox', 'view'));
        $this->bcf->addRoute('Outbox', 'discard', [
            'label' => __('Discard request'),
            'icon' => 'trash',
            'url' => '/outbox/discard/{{id}}',
            'url_vars' => ['id' => 'id'],
        ]);
        $this->bcf->addRoute('Outbox', 'process', [
            'label' => __('Process request'),
            'icon' => 'cogs',
            'url' => '/outbox/process/{{id}}',
            'url_vars' => ['id' => 'id'],
        ]);
    }

    public function addParents()
    {
        $this->bcf->addParent('Outbox', 'view', 'Outbox', 'index');
        $this->bcf->addParent('Outbox', 'discard', 'Outbox', 'index');
        $this->bcf->addParent('Outbox', 'process', 'Outbox', 'index');
    }

    public function addLinks()
    {
        $this->bcf->addSelfLink('Outbox', 'view');
    }

    public function addActions()
    {
        $this->bcf->addAction('Outbox', 'view', 'Outbox', 'process');
        $this->bcf->addAction('Outbox', 'view', 'Outbox', 'discard');
    }
}
