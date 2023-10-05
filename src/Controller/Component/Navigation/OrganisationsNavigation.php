<?php
namespace App\Controller\Component\Navigation;

class OrganisationsNavigation extends BaseNavigation
{

    public function addActions()
    {
        $this->bcf->addCustomAction(
            'Organisations',
            'index',
            '/admin/users/email',
            __('Contact Organisation'),
            [
            'icon' => 'comment-dots',
            ]
        );
    }
}
