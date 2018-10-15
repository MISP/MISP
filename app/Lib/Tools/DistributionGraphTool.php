<?php
    class DistributionGraphTool
    {
        private $__user = false;
        private $__json = array();
        private $__eventModel = false;

        public function construct($eventModel, $servers, $user, $extended_view=0)
        {
            $this->__eventModel = $eventModel;
            $this->__serverList = $servers;
            $this->__organisationModel = $eventModel->Orgc;
            $this->__user = $user;
            $this->__json = array();
            $this->__extended_view = $extended_view;

            // construct distribution info
            $this->__json['distributionInfo'] = array();
            $sgs = $this->__eventModel->SharingGroup->fetchAllAuthorised($this->__user, 'name', 1);
            $this->__json['allSharingGroup'] = h(array_values($sgs));
            $distributionLevels = $this->__eventModel->distributionLevels;
            foreach ($distributionLevels as $key => $value) {
                $this->__json['distributionInfo'][$key] = array('key' => h($value), 'desc' => h($this->__eventModel->distributionDescriptions[$key]['formdesc']), 'value' => h($key));
            }
            $this->__json['distributionInfo'][5] = ""; // inherit event. Will be deleted afterward

            return true;
        }

        private function __extract_sharing_groups_names($sharingArray)
        {
            return $sharingArray['name'];
        }

        private function __fetchAndAddDistributionInfo($elem)
        {
            $distributionLevel = $elem['distribution'];

            if ($distributionLevel == 5) { // inherit -> convert it to the event distribution level
                $elem['distribution'] = $this->__eventDistribution;
                $this->__fetchAndAddDistributionInfo($elem);
            } elseif ($distributionLevel == 4) { // sharing group
                if (isset($elem['SharingGroup'])) {
                    $sg_name = $this->__extract_sharing_groups_names($elem['SharingGroup']);
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
        }

        private function __addOtherDistributionInfo()
        {
            // all comm
            $this->__addAdditionalDistributionInfo(3, "This community"); // add current community
            $this->__addAdditionalDistributionInfo(3, "All other communities"); // add current community

            // connected
            $servers = $this->__serverList;
            $this->__addAdditionalDistributionInfo(2, "This community"); // add current community
            foreach ($servers as $server) {
                $this->__addAdditionalDistributionInfo(2, $server);
            }

            // community
            $orgs = $this->__organisationModel->find('list', array(
                'fields' => array('name'),
            ));
            $thisOrg = $this->__user['Organisation']['name'];
            $this->__addAdditionalDistributionInfo(1, $thisOrg); // add current community
            foreach ($orgs as $org) {
                if ($thisOrg != $org) {
                    $this->__addAdditionalDistributionInfo(1, $org);
                }
            }

            // org only
            $thisOrg = $this->__user['Organisation']['name'];
            $this->__addAdditionalDistributionInfo(0, $thisOrg); // add current community
        }

        private function __get_event($id)
        {
            $fullevent = $this->__eventModel->fetchEvent($this->__user, array('eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1, 'extended' => $this->__extended_view));
            $event = array();
            if (empty($fullevent)) {
                return $event;
            }

            $fullevent = $fullevent[0];
            if (!empty($fullevent['Object'])) {
                $event['Object'] = $fullevent['Object'];
            } else {
                $event['Object'] = array();
            }

            if (!empty($fullevent['Attribute'])) {
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
            $event = $this->__get_event($id);
            $eventDist = $event['distribution'];
            $eventSGName = $event['SharingGroupName'];
            $this->__eventDistribution = $eventDist;
            $this->__eventSharingGroupName = $eventSGName;
            $this->__json['event'] = $this->init_array_distri();
            $this->__json['attribute'] = $this->init_array_distri();
            $this->__json['object'] = $this->init_array_distri();
            $this->__json['obj_attr'] = $this->init_array_distri();
            $this->__json['additionalDistributionInfo'] = $this->init_array_distri(array());


            if (empty($event)) {
                return $this->__json;
            }

            if (!empty($event['Object'])) {
                $object = $event['Object'];
            } else {
                $object = array();
            }

            if (!empty($event['Attribute'])) {
                $attribute = $event['Attribute'];
            } else {
                $attribute = array();
            }

            // extract distribution
            foreach ($attribute as $attr) {
                $distri = $attr['distribution'];
                $this->__json['event'][$distri] += 1;
                $this->__json['attribute'][$distri] += 1;
                $this->__fetchAndAddDistributionInfo($attr);
            }

            foreach ($object as $obj) {
                $distri = $obj['distribution'];
                $this->__json['event'][$distri] += 1;
                $this->__json['object'][$distri] += 1;
                $this->__fetchAndAddDistributionInfo($obj);

                $added_value = array();
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


            $this->__addOtherDistributionInfo();

            // transform set into array
            foreach (array_keys($this->__json['additionalDistributionInfo']) as $d) {
                $this->__json['additionalDistributionInfo'][$d] = array_keys($this->__json['additionalDistributionInfo'][$d]);
            }

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
