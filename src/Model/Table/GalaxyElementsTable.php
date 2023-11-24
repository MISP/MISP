<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Utility\Hash;

/**
 * @property GalaxyCluster $GalaxyCluster
 */
class GalaxyElementsTable extends AppTable
{
    public $useTable = 'galaxy_elements';

    public $recursive = -1;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'GalaxyClusters',
            [
                'foreignKey' => 'galaxy_cluster_id',
            ]
        );
        $this->setDisplayField('name');
    }

    public function updateElements($oldClusterId, $newClusterId, $elements, $delete = true)
    {
        if ($delete) {
            $this->deleteAll(['GalaxyElement.galaxy_cluster_id' => $oldClusterId]);
        }
        $tempElements = [];
        foreach ($elements as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $arrayElement) {
                    $tempElements[] = [
                        'key' => $key,
                        'value' => $arrayElement,
                        'galaxy_cluster_id' => $newClusterId
                    ];
                }
            } else {
                $tempElements[] = [
                    'key' => $key,
                    'value' => $value,
                    'galaxy_cluster_id' => $newClusterId
                ];
            }
        }
        $this->saveMany($tempElements);
    }

    public function update($galaxy_id, $oldClusters, $newClusters)
    {
        $elementsToSave = [];
        // Since we are dealing with flat files as the end all be all content, we are safe to just drop all of the old clusters and recreate them.
        foreach ($oldClusters as $oldCluster) {
            $this->deleteAll(['GalaxyElement.galaxy_cluster_id' => $oldCluster['GalaxyCluster']['id']]);
        }
        foreach ($newClusters as $newCluster) {
            $tempCluster = [];
            foreach ($newCluster as $key => $value) {
                // Don't store the reserved fields as elements
                if ($key == 'description' || $key == 'value') {
                    continue;
                }
                if (is_array($value)) {
                    foreach ($value as $arrayElement) {
                        $tempCluster[] = ['key' => $key, 'value' => $arrayElement];
                    }
                } else {
                    $tempCluster[] = ['key' => $key, 'value' => $value];
                }
            }

            foreach ($tempCluster as $key => $value) {
                $tempCluster[$key]['galaxy_cluster_id'] = $oldCluster['GalaxyCluster']['id'];
            }
            $elementsToSave = array_merge($elementsToSave, $tempCluster);
        }
        $this->saveMany($elementsToSave);
    }

    public function captureElements($user, $elements, $clusterId)
    {
        $tempElements = [];
        foreach ($elements as $k => $element) {
            $tempElements[] = [
                'key' => $element['key'],
                'value' => $element['value'],
                'galaxy_cluster_id' => $clusterId,
            ];
        }
        $this->saveMany($this->newEntities($tempElements));
    }

    public function buildACLConditions($user)
    {
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            $conditions = $this->GalaxyCluster->buildConditions($user);
        }
        return $conditions;
    }

    public function buildClusterConditions($user, $clusterId)
    {
        return [
            $this->buildACLConditions($user),
            'GalaxyClusters.id' => $clusterId
        ];
    }

    public function fetchElements(array $user, $clusterId)
    {
        $params = [
            'conditions' => $this->buildClusterConditions($user, $clusterId),
            'contain' => ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]],
            'recursive' => -1
        ];
        $elements = $this->find('all', $params);
        foreach ($elements as $i => $element) {
            $elements[$i] = $elements[$i]['GalaxyElement'];
            unset($elements[$i]['GalaxyCluster']);
            unset($elements[$i]['GalaxyElement']);
        }
        return $elements;
    }

    public function getExpandedJSONFromElements($elements)
    {
        $keyedValue = [];
        foreach ($elements as $i => $element) {
            $keyedValue[$element['GalaxyElement']['key']][] = $element['GalaxyElement']['value'];
        }
        $expanded = Hash::expand($keyedValue);
        return $expanded;
    }

    /**
     * getClusterIDsFromMatchingElements
     *
     * @param array $user
     * @param array $elements an associative array containg the elements to search for
     *  Example: {"synonyms": "apt42"}
     * @return array
     */
    public function getClusterIDsFromMatchingElements(array $user, array $elements): array
    {
        $conditionCount = 0;
        $elementConditions = [];
        foreach ($elements as $key => $value) {
            $elementConditions['OR'][] = [
                'GalaxyElement.key' => $key,
                'GalaxyElement.value' => $value,
            ];
            $conditionCount += is_array($value) ? count($value) : 1;
        }
        $conditions = [
            $this->buildACLConditions($user),
            $elementConditions,
        ];
        $elements = $this->find(
            'all',
            [
                'fields' => ['GalaxyElement.galaxy_cluster_id'],
                'conditions' => $conditions,
                'contain' => ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]],
                'group' => ['GalaxyElement.galaxy_cluster_id'],
                'having' => ['COUNT(GalaxyElement.id) =' => $conditionCount],
                'recursive' => -1
            ]
        );
        $clusterIDs = [];
        foreach ($elements as $element) {
            $clusterIDs[] = $element['GalaxyElement']['galaxy_cluster_id'];
        }
        return $clusterIDs;
    }
}
