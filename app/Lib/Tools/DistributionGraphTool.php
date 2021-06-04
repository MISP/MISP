<?php
class DistributionGraphTool
{
    /** @var array */
    private $__user;
    private $__json = array();
    /** @var Event */
    private $__eventModel;
    /** @var Organisation */
    private $__organisationModel;
    /** @var array */
    private $__serverList;

    public function construct(Event $eventModel, array $servers, array $user, $extended_view=0)
    {
        $this->__eventModel = $eventModel;
        $this->__serverList = $servers;
        $this->__organisationModel = $eventModel->Orgc;
        $this->__user = $user;
        $this->__json = array();
        $this->__extended_view = $extended_view;

        // construct distribution info
        $sgs = $this->__eventModel->SharingGroup->fetchAllAuthorised($this->__user, 'distribution_graph', true);
        $this->__json['allSharingGroup'] = h($sgs);

        $this->__json['distributionInfo'] = array();
        foreach ($this->__eventModel->distributionLevels as $key => $value) {
            $this->__json['distributionInfo'][$key] = [
                'key' => h($value),
                'desc' => h($this->__eventModel->distributionDescriptions[$key]['formdesc']),
                'value' => h($key)
            ];
        }
        $this->__json['distributionInfo'][5] = ""; // inherit event. Will be deleted afterward

        return true;
    }

    private function __fetchAndAddDistributionInfo($elem)
    {
        $distributionLevel = $elem['distribution'];

        if ($distributionLevel == 5) { // inherit -> convert it to the event distribution level
            $elem['distribution'] = $this->__eventDistribution;
            $this->__fetchAndAddDistributionInfo($elem);
        } elseif ($distributionLevel == 4) { // sharing group
            if (isset($elem['SharingGroup'])) {
                $sg_name = $elem['SharingGroup']['name'];
                $this->__addAdditionalDistributionInfo($distributionLevel, $sg_name);
            } elseif ($this->__eventDistribution == 4) { // event is distributed for sg
                $sg_name = $this->__eventSharingGroupName;
                $this->__addAdditionalDistributionInfo($distributionLevel, $sg_name);
            }
        } else {
            return false;
        }
        return true;
    }

    private function __addAdditionalDistributionInfo($distributionLevel, $data)
    {
        if (empty($this->__json['additionalDistributionInfo'][$distributionLevel])) {
            $this->__json['additionalDistributionInfo'][$distributionLevel] = array();
        }
        $this->__json['additionalDistributionInfo'][$distributionLevel][h($data)] = 0; // set-alike
        if ($distributionLevel == 4) {
            if (!isset($this->__json['sharingGroupRepartition'][h($data)])) {
                $this->__json['sharingGroupRepartition'][h($data)] = 0;
            }
            $this->__json['sharingGroupRepartition'][h($data)]++;
        }
    }

    private function __addOtherDistributionInfo()
    {
        // all comm
        $this->__addAdditionalDistributionInfo(3, "This community"); // add current community
        $this->__addAdditionalDistributionInfo(3, "All other communities"); // add current community

        // connected
        $this->__addAdditionalDistributionInfo(2, "This community"); // add current community
        foreach ($this->__serverList as $server) {
            $this->__addAdditionalDistributionInfo(2, $server);
        }

        // community
        $orgConditions = $this->__organisationModel->createConditions($this->__user);
        $orgConditions['local'] = true;
        $orgConditions['id !='] = $this->__user['Organisation']['id'];
        $orgs = $this->__organisationModel->find('column', array(
            'fields' => ['name'],
            'conditions' => $orgConditions,
        ));
        $thisOrg = $this->__user['Organisation']['name'];
        $this->__addAdditionalDistributionInfo(1, $thisOrg); // add current community
        foreach ($orgs as $orgName) {
            $this->__addAdditionalDistributionInfo(1, $orgName);
        }

        // org only
        $this->__addAdditionalDistributionInfo(0, $thisOrg); // add current community
    }

    /**
     * Fetch event containing just 'Attribute', 'Object', 'SharingGroup' and 'distribution'
     * @param int $id
     * @return array
     * @throws Exception
     */
    private function __get_event($id)
    {
        $fullevent = $this->__eventModel->fetchEvent($this->__user, array(
            'eventid' => $id,
            'flatten' => 0,
            'noShadowAttributes' => true,
            'noEventReports' => true,
            'noSightings' => true,
            'excludeGalaxy' => true,
            'includeEventCorrelations' => false,
            'extended' => $this->__extended_view,
        ));
        $event = array();
        if (empty($fullevent)) {
            return $event;
        }

        $fullevent = $fullevent[0];
        if (isset($fullevent['Object'])) {
            $event['Object'] = $fullevent['Object'];
        } else {
            $event['Object'] = array();
        }

        if (isset($fullevent['Attribute'])) {
            $event['Attribute'] = $fullevent['Attribute'];
        } else {
            $event['Attribute'] = array();
        }
        $event['distribution'] = $fullevent['Event']['distribution'];

        if (isset($fullevent['SharingGroup'])) {
            $event['SharingGroupName'] = $fullevent['SharingGroup']['name'];
        } else {
            $event['SharingGroupName'] = "?";
        }

        return $event;
    }

    public function get_distributions_graph($id)
    {
        $this->__json['event'] = $this->init_array_distri();
        $this->__json['attribute'] = $this->init_array_distri();
        $this->__json['object'] = $this->init_array_distri();
        $this->__json['obj_attr'] = $this->init_array_distri();
        $this->__json['additionalDistributionInfo'] = $this->init_array_distri(array());
        $this->__json['sharingGroupRepartition'] = array();

        $this->__addOtherDistributionInfo();

        // transform set into array
        foreach (array_keys($this->__json['additionalDistributionInfo']) as $d) {
            $this->__json['additionalDistributionInfo'][$d] = array_keys($this->__json['additionalDistributionInfo'][$d]);
        }

        if ($id === -1) {
            return $this->__json;
        }
        $event = $this->__get_event($id);
        if (empty($event)) {
            return $this->__json;
        }

        $eventDist = $event['distribution'];
        $eventSGName = $event['SharingGroupName'];
        $this->__eventDistribution = $eventDist;
        $this->__eventSharingGroupName = $eventSGName;

        // extract distribution
        foreach ($event['Attribute'] as $attr) {
            $distri = $attr['distribution'];
            $this->__json['event'][$distri] += 1;
            $this->__json['attribute'][$distri] += 1;
            $this->__fetchAndAddDistributionInfo($attr);
        }

        foreach ($event['Object'] as $obj) {
            $distri = $obj['distribution'];
            $this->__json['event'][$distri] += 1;
            $this->__json['object'][$distri] += 1;
            $this->__fetchAndAddDistributionInfo($obj);

            if (!empty($obj['Attribute'])) {
                foreach ($obj['Attribute'] as $objAttr) {
                    $distri = $objAttr['distribution'];
                    $this->__json['event'][$distri] += 1;
                    $this->__json['obj_attr'][$distri] += 1;
                    $this->__fetchAndAddDistributionInfo($objAttr);
                }
            }
        }
        // distribution 5 is inherit event, apply this fact on values
        $this->__json['event'][$eventDist] += $this->__json['event'][5];
        unset($this->__json['event'][5]);
        $this->__json['attribute'][$eventDist] += $this->__json['attribute'][5];
        unset($this->__json['attribute'][5]);
        $this->__json['object'][$eventDist] += $this->__json['object'][5];
        unset($this->__json['object'][5]);
        $this->__json['obj_attr'][$eventDist] += $this->__json['obj_attr'][5];
        unset($this->__json['obj_attr'][5]);

        unset($this->__json['distributionInfo'][5]); // inherit event.

        // transform set into array for SG (others are already done)
        $this->__json['additionalDistributionInfo'][4] = array_keys($this->__json['additionalDistributionInfo'][4]);

        return $this->__json;
    }

    public function init_array_distri($default=0)
    {
        $ret = array();
        foreach ($this->__json['distributionInfo'] as $d => $v) {
            $ret[h($d)] = $default;
        }
        return $ret;
    }
}
