<?php
App::uses('AppModel', 'Model');

/**
 * @property GalaxyCluster $GalaxyCluster
 */
class GalaxyElement extends AppModel
{
    public $useTable = 'galaxy_elements';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
            'Containable',
    );

    public $belongsTo = array(
            'GalaxyCluster' => array(
                'className' => 'GalaxyCluster',
                'foreignKey' => 'galaxy_cluster_id',
            )
    );

    public function updateElements($oldClusterId, $newClusterId, $elements, $delete=true)
    {
        if ($delete) {
            $this->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $oldClusterId));
        }
        $tempElements = array();
        foreach ($elements as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $arrayElement) {
                    $tempElements[] = array(
                        'key' => $key,
                        'value' => $arrayElement,
                        'galaxy_cluster_id' => $newClusterId
                    );
                }
            } else {
                $tempElements[] = array(
                    'key' => $key,
                    'value' => $value,
                    'galaxy_cluster_id' => $newClusterId
                );
            }
        }
        $this->saveMany($tempElements);
    }

    public function captureElements($user, $elements, $clusterId)
    {
        $tempElements = array();
        foreach ($elements as $k => $element) {
            $tempElements[] = array(
                'key' => $element['key'],
                'value' => $element['value'],
                'galaxy_cluster_id' => $clusterId,
            );
        }
        $this->saveMany($tempElements);
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
            'GalaxyCluster.id' => $clusterId
        ];
    }

    public function fetchElements(array $user, $clusterId)
    {
        $params = array(
            'conditions' => $this->buildClusterConditions($user, $clusterId),
            'contain' => ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]],
            'recursive' => -1
        );
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
        $elements = $this->find('all', [
            'fields' => ['GalaxyElement.galaxy_cluster_id'],
            'conditions' => $conditions,
            'contain' => ['GalaxyCluster' => ['fields' => ['id', 'distribution', 'org_id']]],
            'group' => ['GalaxyElement.galaxy_cluster_id'],
            'having' => ['COUNT(GalaxyElement.id) =' => $conditionCount],
            'recursive' => -1
        ]);
        $clusterIDs = [];
        foreach ($elements as $element) {
            $clusterIDs[] = $element['GalaxyElement']['galaxy_cluster_id'];
        }
        return $clusterIDs;
    }
}
