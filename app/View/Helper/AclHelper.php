<?php
App::uses('Helper', 'View');

class AclHelper extends Helper
{
    /** @var ACLComponent */
    private $ACL;

    /** @var array */
    private $me;

    public function __construct(View $View, $settings = [])
    {
        parent::__construct($View, $settings);

        $this->ACL = $View->viewVars['aclComponent'];
        if (!$this->ACL instanceof ACLComponent) {
            throw new InvalidArgumentException('ACL not provided.');
        }

        $this->me = $View->viewVars['me'];
        if (empty($this->me)) {
            throw new InvalidArgumentException('Me variable not provided.');
        }
    }

    /**
     * @param string $controller
     * @param string $action
     * @return bool
     */
    public function canAccess($controller, $action)
    {
        return $this->ACL->canUserAccess($this->me, $controller, $action);
    }

    /**
     * @param array $event
     * @return bool
     */
    public function canModifyEvent(array $event)
    {
        return $this->ACL->canModifyEvent($this->me, $event);
    }

    /**
     * @param array $event
     * @return bool
     */
    public function canPublishEvent(array $event)
    {
        return $this->ACL->canPublishEvent($this->me, $event);
    }

    /**
     * @param array $event
     * @param bool $isTagLocal
     * @return bool
     */
    public function canModifyTag(array $event, $isTagLocal = false)
    {
        return $this->ACL->canModifyTag($this->me, $event, $isTagLocal);
    }

    /**
     * @param array $event
     * @return bool
     */
    public function canDisableCorrelation(array $event)
    {
        return $this->ACL->canDisableCorrelation($this->me, $event);
    }

    /**
     * @param array $tagCollection
     * @return bool
     */
    public function canModifyTagCollection(array $tagCollection)
    {
        return $this->ACL->canModifyTagCollection($this->me, $tagCollection);
    }

    /**
     * @param array $sighting
     * @return bool
     */
    public function canDeleteSighting(array $sighting)
    {
        return $this->ACL->canDeleteSighting($this->me, $sighting);
    }

    /**
     * @param array $eventReport
     * @return bool
     */
    public function canEditEventReport(array $eventReport)
    {
        return $this->ACL->canEditEventReport($this->me, $eventReport);
    }

    /**
     * @param array $cluster
     * @return bool
     */
    public function canModifyGalaxyCluster(array $cluster)
    {
        return $this->ACL->canModifyGalaxyCluster($this->me, $cluster);
    }

    /**
     * @param array $cluster
     * @return bool
     */
    public function canPublishGalaxyCluster(array $cluster)
    {
        return $this->ACL->canModifyGalaxyCluster($this->me, $cluster);
    }

    /**
     * @param array $cluster
     * @return bool
     */
    public function canEditAnalystData(array $analystData, $modelType): bool
    {
        return $this->ACL->canEditAnalystData($this->me, $analystData, $modelType);
    }
}