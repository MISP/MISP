<?php
App::uses('AppModel', 'Model');
class GalaxyCluster extends AppModel{

	public $useTable = 'galaxy_clusters';

	public $recursive = -1;

	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
	);

	public $belongsTo = array(
		'Galaxy' => array(
			'className' => 'Galaxy',
			'foreignKey' => 'galaxy_id',
		),
		'Tag' => array(
			'foreignKey' => false,
			'conditions' => array('GalaxyCluster.tag_name = Tag.name')
		)
	);


	public $hasMany = array(
		'GalaxyElement' => array('dependent' => true),
	//	'GalaxyReference'
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		if (!isset($this->data['GalaxyCluster']['description'])) {
			$this->data['GalaxyCluster']['description'] = '';
		}
		return true;
	}

	public function beforeDelete($cascade = true) {
		$this->GalaxyElement->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $this->id));
	}


	// receive a full galaxy and add all new clusters, update existing ones contained in the new galaxy, cull old clusters that are removed from the galaxy
	public function update($id, $galaxy) {
		$existingClusters = $this->find('all', array(
			'conditions' => array('GalaxyCluster.galaxy_id' => $id),
			'recursive' => -1,
		));
		foreach ($galaxy['values'] as $cluster) {
			$oldCluster = false;
			if (!empty($existingClusters)) {
				foreach ($existingClusters as $k => $existingCluster) {
					if ($existingCluster['GalaxyCluster']['value'] == $cluster['value']) {
						$oldCluster = true;
						if ($cluster['description'] != $existingCluster['GalaxyCluster']['description']) {
							$existingCluster['GalaxyCluster']['description'] = $cluster['description'];
							$this->GalaxyElement->deleteAll('galaxy_cluster_id' == $existingCluster['GalaxyCluster']['id']);
							$this->save($existingCluster);
							$template = array('galaxy_cluster_id' => $this->id);
							$toSave = array();
							foreach ($cluster as $key => $value) {
								if (in_array($key, array('value', 'description'))) {
									continue;
								}
								$tosave[] = array_merge($template, array('key' => $key, 'value' => $value));
							}
							$this->GalaxyElement->saveMany($toSave);
						}
						unset($existingClusters[$k]);
					}
				}
			}
			if (!$oldCluster) {
				$newCluster = array_intersect_key($cluster, array_flip(array('value', 'description')));
				$newCluster['galaxy_id'] = $id;
				$newCluster['type'] = $galaxy['type'];
				$toSave[] = $newCluster;
			}
			$final = array();
			if (!empty($existingCluster)) {
				$fieldsToUpdate = array('description', '');
				$final = $existingCluster;
			}
		}
		$this->saveMany($toSave);
		// Let's retrieve the full list of clusters we have for the given galaxy and pass it to the element system
		$existingClusters = $this->find('all', array(
				'conditions' => array('GalaxyCluster.galaxy_id'),
				'contain' => array('GalaxyElement'/*, 'GalaxyReference'*/)
		));
		$this->GalaxyElement->update($id, $existingClusters, $galaxy['values']);
	}

	/* Return a list of all tags associated with the cluster specific cluster within the galaxy (or all clusters if $clusterValue is false)
	 * The counts are restricted to the event IDs that the user is allowed to see.
	*/
	public function getTags($galaxyType, $clusterValue = false, $user) {
		$this->Event = ClassRegistry::init('Event');
		$event_ids = $this->Event->fetchEventIds($user, false, false, false, true);
		$tags = $this->Event->EventTag->Tag->find('list', array(
				'conditions' => array('name LIKE' => 'misp-galaxy:' . $galaxyType . '="' . ($clusterValue ? $clusterValue : '%') .'"'),
				'fields' => array('name', 'id'),
		));
		$this->Event->EventTag->virtualFields['tag_count'] = 'COUNT(id)';
		$tagCounts = $this->Event->EventTag->find('list', array(
				'conditions' => array('EventTag.tag_id' => array_values($tags), 'EventTag.event_id' => $event_ids),
				'fields' => array('EventTag.tag_id', 'EventTag.tag_count'),
				'group' => array('EventTag.tag_id')
		));
		foreach ($tags as $k => $v) {
			if (isset($tagCounts[$v])) {
				$tags[$k] = array('count' => $tagCounts[$v], 'tag_id' => $v);
			} else {
				unset($tags[$k]);
			}
		}
		return $tags;
	}

	/* Fetch a cluster along with all elements and the galaxy it belongs to
	 *   - In the future, once we move to galaxy 2.0, pass a user along for access control
	 *   - maybe in the future remove the galaxy itself once we have logos with each galaxy
	*/
	public function getCluster($name) {
		$conditions = array('GalaxyCluster.tag_name ' => $name);
		if (is_numeric($name)) {
			$conditions = array('GalaxyCluster.id' => $name);
		}
		$objects = array('Galaxy', 'GalaxyElement');
		$cluster = $this->find('first', array(
			'conditions' => $conditions,
			'contain' => array('Galaxy', 'GalaxyElement')
		));
		if (!empty($cluster)) {
			$cluster['GalaxyCluster']['authors'] = json_decode($cluster['GalaxyCluster']['authors'], true);
			if (isset($cluster['Galaxy'])) {
				$cluster['GalaxyCluster']['Galaxy'] = $cluster['Galaxy'];
				unset($cluster['Galaxy']);
			}
			$elements = array();
			foreach ($cluster['GalaxyElement'] as $element) {
				if (!isset($elements[$element['key']])) {
					$elements[$element['key']] = array($element['value']);
				} else {
					$elements[$element['key']][] = $element['value'];
				}
			}
			unset($cluster['GalaxyElement']);
			$this->Tag = ClassRegistry::init('Tag');
			$tag_id = $this->Tag->find('first', array(
					'conditions' => array(
							'Tag.name' => $cluster['GalaxyCluster']['tag_name']
					),
					'recursive' => -1,
					'fields' => array('Tag.id')
				)
			);
			if (!empty($tag_id)) {
				$cluster['GalaxyCluster']['tag_id'] = $tag_id['Tag']['id'];
			}
			$cluster['GalaxyCluster']['meta'] = $elements;
		}
		return $cluster;
	}

	public function attachClustersToEventIndex($events, $replace = false) {
		foreach ($events as $k => $event) {
			foreach ($event['EventTag'] as $k2 => $eventTag) {
				if (substr($eventTag['Tag']['name'], 0, strlen('misp-galaxy:')) === 'misp-galaxy:') {
					$cluster = $this->getCluster($eventTag['Tag']['name']);
					if ($cluster) {
						$cluster['GalaxyCluster']['tag_id'] = $eventTag['Tag']['id'];
						$events[$k]['GalaxyCluster'][] = $cluster['GalaxyCluster'];
						if ($replace) {
							unset($events[$k]['EventTag'][$k2]);
						}
					}
				}
			}
		}
		return $events;
	}
}
