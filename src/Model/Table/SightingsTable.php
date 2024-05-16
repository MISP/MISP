<?php

namespace App\Model\Table;

use App\Lib\Tools\ServerSyncTool;
use App\Model\Entity\Sighting;
use App\Model\Entity\User;
use App\Model\Table\AppTable;
use Cake\Core\Configure;

class SightingsTable extends AppTable
{
    private $orgCache = [];

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->belongsTo(
            'Attribute',
            [
                'className' => 'Attributes',
                'foreignKey' => 'old_id'
            ]
        );
        $this->belongsTo(
            'Event',
            [
                'className' => 'Events',
                'foreignKey' => 'event_id'
            ]
        );
        $this->belongsTo(
            'Organisation',
            [
                'className' => 'Organisations',
                'foreignKey' => 'org_id'
            ]
        );
    }

    /**
     * @param User $user
     * @param ServerSyncTool $serverSync
     * @return int Number of saved Sightings.
     * @throws Exception
     */
    public function pullSightings(User $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pullSightings() method.

        return 0;
    }

    /**
     * Push sightings to remote server.
     * @param User $user
     * @param ServerSyncTool $serverSync
     * @return array
     * @throws Exception
     */
    public function pushSightings(User $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pushSightings() method.

        return [];
    }

    /**
     * @param array $event Just 'Event' object is enough
     * @param User $user
     * @param array|int|null $attribute Attribute model or attribute ID
     * @param array|bool $extraConditions
     * @param bool $forSync
     * @return array|int
     */
    public function attachToEvent(array $event, User $user, $attribute = null, $extraConditions = false, $forSync = false)
    {
        $conditions = $this->createConditions($user->toArray(), $event);
        if ($conditions === false) {
            return [];
        }

        $conditions['Sightings.event_id'] = $event['id'];
        if (isset($attribute['Attribute']['id'])) {
            $conditions['Sightings.attribute_id'] = $attribute['Attribute']['id'];
        } elseif (is_numeric($attribute)) {
            $conditions['Sightings.attribute_id'] = $attribute;
            $attribute = $this->Attribute->find(
                'first',
                [
                    'recursive' => -1,
                    'conditions' => ['Attributes.id' => $attribute],
                    'fields' => ['Attributes.uuid']
                ]
            );
        }

        if ($extraConditions !== false) {
            $conditions['AND'] = $extraConditions;
        }
        $sightings = $this->find(
            'all',
            [
                'conditions' => $conditions,
                'recursive' => -1,
            ]
        );
        if (empty($sightings)) {
            return [];
        }
        if ($attribute === null) {
            // Do not add attribute uuid in contain query, joining is slow and takes more memory
            $attributeUuids = $this->Attribute->find(
                'all',
                [
                    'conditions' => ['event_id' => $event['id']],
                    'fields' => ['id', 'uuid'],
                    'recursive' => -1,
                ]
            )->toArray();
            // `array_column` is much faster than find('list')
            $attributeUuids = array_column(array_column($attributeUuids, 'Attribute'), 'uuid', 'id');
            foreach ($sightings as $k => $sighting) {
                $sighting['Sighting']['attribute_uuid'] = $attributeUuids[$sighting['Sighting']['attribute_id']];
                $sightings[$k] = $sighting;
            }
            unset($attributeUuids);
        } else {
            foreach ($sightings as $k => $sighting) {
                $sighting['Sighting']['attribute_uuid'] = $attribute['Attribute']['uuid'];
                $sightings[$k] = $sighting;
            }
        }
        return $this->attachOrgToSightings($sightings->toArray(), $user, $forSync);
    }

    /**
     * @param array $user
     * @param array $event
     * @return array|false
     */
    private function createConditions(array $user, array $event)
    {
        $sightingsPolicy = $this->sightingsPolicy();
        $ownEvent = $user['Role']['perm_site_admin'] || $event['org_id'] == $user['org_id'];
        if (!$ownEvent) {
            if ($sightingsPolicy === Sighting::SIGHTING_POLICY_EVENT_OWNER) {
                return ['Sightings.org_id' => $user['org_id']];
            } else if ($sightingsPolicy === Sighting::SIGHTING_POLICY_SIGHTING_REPORTER) {
                if (!$this->isReporter($event['id'], $user['org_id'])) {
                    return false;
                }
            } else if ($sightingsPolicy === Sighting::SIGHTING_POLICY_HOST_ORG) {
                return ['Sightings.org_id' => [$user['org_id'], Configure::read('MISP.host_org_id')]];
            }
        }
        return [];
    }

    /**
     * @return int
     */
    private function sightingsPolicy()
    {
        $policy = Configure::read('Plugin.Sightings_policy');
        if ($policy === null) { // default policy
            return Sighting::SIGHTING_POLICY_EVENT_OWNER;
        }
        return (int)$policy;
    }

    /**
     * @param array $sightings
     * @param User $user
     * @param false $forSync
     * @return array
     */
    private function attachOrgToSightings(array $sightings, User $user, $forSync = false)
    {
        $showOrg = Configure::read('MISP.showorg');
        $anonymise = Configure::read('Plugin.Sightings_anonymise');
        $anonymiseAs = Configure::read('Plugin.Sightings_anonymise_as');

        $anonOrg = null;
        if ($forSync && !empty($anonymiseAs)) {
            $anonOrg = $this->getOrganisationById($anonymiseAs);
        }

        foreach ($sightings as $k => $sighting) {
            $sighting = $sighting['Sighting'];
            if ($showOrg && $sighting['org_id']) {
                $sighting['Organisation'] = $this->getOrganisationById($sighting['org_id']);
            }
            if ($sighting['org_id'] != $user['org_id'] && $anonymise) {
                if (empty($anonOrg)) {
                    unset($sighting['org_id']);
                    unset($sighting['Organisation']);
                } else {
                    $sighting['org_id'] = $anonOrg['id'];
                    $sighting['Organisation'] = $anonOrg;
                }
            }
            $sightings[$k] = $sighting;
        }
        $this->orgCache = []; // clear org cache
        return $sightings;
    }

    /**
     * @param array $events
     * @param array $user
     * @param bool $csvWithFalsePositive
     * @return array
     */
    public function eventsStatistic(array $events, array $user, $csvWithFalsePositive = false)
    {
        if (empty($events)) {
            return ['data' => [], 'csv' => []];
        }

        $sightingsPolicy = $this->sightingsPolicy();

        $conditions = [];
        foreach ($events as $event) {
            $eventCondition = ['Sighting.event_id' => $event['id']];
            $ownEvent = $user['Role']['perm_site_admin'] || $event['org_id'] == $user['org_id'];
            if (!$ownEvent) {
                if ($sightingsPolicy === Sighting::SIGHTING_POLICY_EVENT_OWNER) {
                    $eventCondition['Sighting.org_id'] = $user['org_id'];
                } else if ($sightingsPolicy === Sighting::SIGHTING_POLICY_SIGHTING_REPORTER) {
                    if (!$this->isReporter($event['id'], $user['org_id'])) {
                        continue;
                    }
                } else if ($sightingsPolicy === Sighting::SIGHTING_POLICY_HOST_ORG) {
                    $eventCondition['Sighting.org_id'] = [$user['org_id'], Configure::read('MISP.host_org_id')];
                }
            }
            $conditions['OR'][] = $eventCondition;
        }

        // TODO: [3.x-MIGRATION] review this, relies on virtual fields in a way that is not compatible with cakephp4
        // $groupedSightings = $this->fetchGroupedSightings($conditions, $user);
        $groupedSightings = [];

        return $this->generateStatistics($groupedSightings, $csvWithFalsePositive);
    }

    /**
     * @param array $groupedSightings
     * @param bool $csvWithFalsePositive
     * @return array[]
     */
    private function generateStatistics(array $groupedSightings, $csvWithFalsePositive = false)
    {
        $sightingsData = [];
        $sparklineData = [];
        $range = $this->getMaximumRange();
        foreach ($groupedSightings as $sighting) {
            $type = Sighting::TYPE[$sighting['type']];
            $orgName = isset($sighting['Organisation']['name']) ? $sighting['Organisation']['name'] : __('Others');
            $count = (int)$sighting['sighting_count'];
            $inRange = strtotime($sighting['date']) >= $range;

            foreach ([$sighting['attribute_id'], 'all'] as $needle) {
                if (!isset($sightingsData[$needle][$type])) {
                    $sightingsData[$needle][$type] = ['count' => 0, 'orgs' => []];
                }

                $ref = &$sightingsData[$needle][$type];
                $ref['count'] += $count;

                if (!isset($ref['orgs'][$orgName])) {
                    $ref['orgs'][$orgName] = ['count' => $count, 'date' => $sighting['last_timestamp']];
                } else {
                    $ref['orgs'][$orgName]['count'] += $count;
                    $ref['orgs'][$orgName]['date'] = $sighting['last_timestamp'];
                }

                if ($inRange) {
                    if (isset($sparklineData[$needle][$sighting['date']][$type])) {
                        $sparklineData[$needle][$sighting['date']][$type] += $count;
                    } else {
                        $sparklineData[$needle][$sighting['date']][$type] = $count;
                    }
                }
            }
        }
        return ['data' => $sightingsData, 'csv' => $this->generateSparkline($sparklineData, $csvWithFalsePositive)];
    }

    /**
     * @return int Timestamp
     */
    public function getMaximumRange()
    {
        $rangeInDays = Configure::read('MISP.Sightings_range');
        $rangeInDays = (!empty($rangeInDays) && is_numeric($rangeInDays)) ? $rangeInDays : 365;
        return strtotime("-$rangeInDays days");
    }

    /**
     * @param array $sparklineData
     * @param bool $csvWithFalsePositive
     * @return array
     */
    private function generateSparkline(array $sparklineData, $csvWithFalsePositive)
    {
        $todayString = date('Y-m-d');
        $today = strtotime($todayString);

        // If nothing found, generate default "empty" CSV for 'all'
        if (!isset($sparklineData['all'])) {
            $sparklineData['all'][$todayString] = null;
        }

        $csv = [];
        foreach ($sparklineData as $object => $data) {
            $startDate = key($data); // oldest date for sparkline
            $startDate = strtotime($startDate) - (Sighting::ONE_DAY * 3);
            $csvForObject = $csvWithFalsePositive ? 'Date,Sighting,False-positive\n' : 'Date,Close\n';
            for ($date = $startDate; $date <= $today; $date += Sighting::ONE_DAY) {
                $dateAsString = date('Y-m-d', $date);
                $csvForObject .= $dateAsString . ',' . (isset($data[$dateAsString]['sighting']) ? $data[$dateAsString]['sighting'] : '0');

                if ($csvWithFalsePositive) {
                    $csvForObject .= ',' . (isset($data[$dateAsString]['false-positive']) ? $data[$dateAsString]['false-positive'] : '0');
                }

                $csvForObject .= '\n';
            }
            $csv[$object] = $csvForObject;
        }
        return $csv;
    }
}
