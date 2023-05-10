<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php'); 

class EventsNavigation extends BaseNavigation
{
    function addRoutes()
    {
    }
    
    public function addParents()
    {
    }
    
    public function addLinks()
    {
        $passedData = $this->request->getParam('pass');
        $eventID = $passedData[0] ?? 0;

        $this->bcf->removeAction('Events', 'view', 'Events', 'delete');

        $this->bcf->addCustomLink('Events', 'view', '/logs/event_index', __('View history'), [
            'url' => sprintf('/logs/event_index/%s', h($eventID)),
            'icon' => 'clock-rotate-left',
        ]);
        $this->bcf->addCustomLink('Events', 'view', '/events/viewgraph', __('Explore'), [
            'url' => sprintf('/events/viewgraph/%s', h($eventID)),
            'icon' => 'binoculars',
        ]);
    }
    
    public function addActions()
    {
        /* Add */
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Add Object', [
            'menu' => 'add',
            'menu_primary' => true,
            'icon' => $this->bcf->iconToTableMapping['Objects'],
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Add Attribute', [
            'menu' => 'add',
            'icon' => $this->bcf->iconToTableMapping['Attributes'],
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Add Report', [
            'menu' => 'add',
            'icon' => $this->bcf->iconToTableMapping['EventReports'],
        ]);

        /* Publish */
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Publish', [
            'menu' => 'publish',
            'icon' => 'paper-plane',
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Unpublish', [
            'menu' => 'publish',
            'icon' => ['stacked' => [
                ['icon' => 'ban', 'class' => 'text-muted',],
                ['icon' => 'paper-plane', 'class' => 'text-body',]
            ]],
            'variant' => 'warning',
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Publish no email', [
            'menu' => 'publish',
            'icon' => ['stacked' => [
                ['icon' => 'ban', 'class' => 'text-muted',],
                ['icon' => 'envelope', 'class' => 'text-body',]
            ]],
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Publish to ZMQ', [
            'menu' => 'publish',
        ]);

        /* Events Action */
        $this->bcf->registerActionMenuConfig('Events', 'view', 'event-actions', [
            'label' => 'Event Actions',
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Enrich event', [
            'menu' => 'event-actions',
            'icon' => 'brain',
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Extend event', [
            'menu' => 'event-actions',
            'icon' => 'expand',
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Contact Org', [
            'menu' => 'event-actions',
            'icon' => 'comment-dots',
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Delete Event', [
            'menu' => 'event-actions',
            'icon' => 'trash',
            'variant' => 'danger',
        ]);

        /* Events Action */
        $this->bcf->registerActionMenuConfig('Events', 'view', 'import-export', [
            'label' => 'Import/Export',
            'icon' => [
                'icon' => 'arrow-right-arrow-left',
                'class' => 'fa-rotate-90 me-1',
            ],
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Populate from', [
            'menu' => 'import-export',
            'icon' => 'puzzle-piece',
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Merge from', [
            'menu' => 'import-export',
            'icon' => 'object-group',
        ]);
        $this->bcf->addCustomAction('Events', 'view', '/link', 'Download as', [
            'menu' => 'import-export',
            'icon' => 'download',
        ]);
    }
}
