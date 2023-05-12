<?php
namespace BreadcrumbNavigation;

class BaseNavigation
{
    protected $bcf;
    protected $request;
    protected $viewVars;
    public $currentUser;
    public $currentUserId;

    public function __construct($bcf, $request, $viewVars)
    {
        $this->bcf = $bcf;
        $this->request = $request;
        if (!empty($this->request->getAttribute('identity'))) {
            $this->currentUserId = $this->request->getAttribute('identity')->getIdentifier();
        }
        $this->viewVars = $viewVars;
    }

    public function setCurrentUser($currentUser)
    {
        $this->currentUser = $currentUser;
    }

    public function addRoutes() {}
    public function addParents() {}
    public function addLinks() {}
    public function addActions() {}
}
