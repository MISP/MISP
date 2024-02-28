<?php

namespace App\Model\Table;

use App\Lib\Tools\ServerSyncTool;
use App\Model\Entity\Sighting;
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
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return int Number of saved Sightings.
     * @throws Exception
     */
    public function pullSightings(array $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pullSightings() method.

        return 0;
    }

    /**
     * Push sightings to remote server.
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return array
     * @throws Exception
     */
    public function pushSightings(array $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pushSightings() method.

        return [];
    }

    /**
     * @param array $event Just 'Event' object is enough
     * @param array $user
     * @param array|int|null $attribute Attribute model or attribute ID
     * @param array|bool $extraConditions
     * @param bool $forSync
     * @return array|int
     */
    public function attachToEvent(array $event, array $user, $attribute = null, $extraConditions = false, $forSync = false)
    {
        $conditions = $this->createConditions($user, $event);
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
     * @param array $user
     * @param false $forSync
     * @return array
     */
    private function attachOrgToSightings(array $sightings, array $user, $forSync = false)
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
}
