<?php
App::uses('AppModel', 'Model');
class GalaxyElement extends AppModel
{
    public $useTable = 'galaxy_elements';

    public $recursive = -1;

    public $actsAs = array(
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
}
