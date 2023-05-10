<?php
namespace BreadcrumbNavigation;

require_once(APP . 'Controller' . DS . 'Component' . DS . 'Navigation' . DS . 'base.php');

class OrganisationsNavigation extends BaseNavigation
{

    public function addActions()
    {
        $this->bcf->addCustomAction('Organisations', 'index', '/admin/users/email', __('Contact Organisation'), [
            'icon' => 'comment-dots',
        ]);
    }
}
