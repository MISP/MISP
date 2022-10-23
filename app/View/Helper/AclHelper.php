<?php
App::uses('Helper', 'View');

class AclHelper extends Helper
{
    /** @var ACLComponent */
    private $ACL;

    public function __construct(View $View, $settings = [])
    {
        parent::__construct($View, $settings);
        $this->ACL = $View->viewVars['aclComponent'];
    }

    /**
     * @param string $controller
     * @param string $action
     * @return bool
     */
    public function canAccess($controller, $action)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canUserAccess($me, $controller, $action);
    }
}