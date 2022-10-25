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

    /**
     * @param array $event
     * @return bool
     */
    public function canModifyEvent(array $event)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canModifyEvent($me, $event);
    }

    /**
     * @param array $event
     * @return bool
     */
    public function canPublishEvent(array $event)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canPublishEvent($me, $event);
    }

    /**
     * @param array $event
     * @param bool $isTagLocal
     * @return bool
     */
    public function canModifyTag(array $event, $isTagLocal = false)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canModifyTag($me, $event, $isTagLocal);
    }

    /**
     * @param array $event
     * @return bool
     */
    public function canDisableCorrelation(array $event)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canDisableCorrelation($me, $event);
    }

    /**
     * @param array $tagCollection
     * @return bool
     */
    public function canModifyTagCollection(array $tagCollection)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canModifyTagCollection($me, $tagCollection);
    }

    /**
     * @param array $sighting
     * @return bool
     */
    public function canDeleteSighting(array $sighting)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canDeleteSighting($me, $sighting);
    }

    /**
     * @param array $eventReport
     * @return bool
     */
    public function canEditEventReport(array $eventReport)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canEditReport($me, $eventReport);
    }

    /**
     * @param array $cluster
     * @return bool
     */
    public function canModifyGalaxyCluster(array $cluster)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canModifyGalaxyCluster($me, $cluster);
    }

    /**
     * @param array $cluster
     * @return bool
     */
    public function canPublishGalaxyCluster(array $cluster)
    {
        $me = $this->_View->viewVars['me'];
        return $this->ACL->canModifyGalaxyCluster($me, $cluster);
    }
}