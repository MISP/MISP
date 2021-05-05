<?php
App::uses('AppModel', 'Model');
class GalaxyElement extends AppModel
{
    public $useTable = 'galaxy_elements';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
            'Containable',
    );

    public $validate = array(
    );

    public $belongsTo = array(
            'GalaxyCluster' => array(
                'className' => 'GalaxyCluster',
                'foreignKey' => 'galaxy_cluster_id',
            )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        return true;
    }

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

    public function update($galaxy_id, $oldClusters, $newClusters)
    {
        $elementsToSave = array();
        // Since we are dealing with flat files as the end all be all content, we are safe to just drop all of the old clusters and recreate them.
        foreach ($oldClusters as $oldCluster) {
            $this->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $oldCluster['GalaxyCluster']['id']));
        }
        foreach ($newClusters as $newCluster) {
            $tempCluster = array();
            foreach ($newCluster as $key => $value) {
                // Don't store the reserved fields as elements
                if ($key == 'description' || $key == 'value') {
                    continue;
                }
                if (is_array($value)) {
                    foreach ($value as $arrayElement) {
                        $tempCluster[] = array('key' => $key, 'value' => $arrayElement);
                    }
                } else {
                    $tempCluster[] = array('key' => $key, 'value' => $value);
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
}
