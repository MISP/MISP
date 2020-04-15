<?php
App::uses('AppModel', 'Model');
class GalaxyCluster extends AppModel
{
    public $useTable = 'galaxy_clusters';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'name' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            )
        ),
        'description' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            )
        ),
        'uuid' => array(
            'uuid' => array(
                'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
                'message' => 'Please provide a valid UUID'
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'required' => 'create'
            )
        ),
        'distribution' => array(
            'rule' => array('inList', array('0', '1', '2', '3', '4', '5')),
            'message' => 'Options: Your organisation only, This community only, Connected communities, All communities, Sharing group, Inherit event',
            'required' => true
        )
    );

    public $belongsTo = array(
        'Galaxy' => array(
            'className' => 'Galaxy',
            'foreignKey' => 'galaxy_id',
        ),
        'Tag' => array(
            'foreignKey' => false,
            'conditions' => array('GalaxyCluster.tag_name = Tag.name')
        ),
        'Org' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        ),
        'Orgc' => array(
            'className' => 'Organisation',
            'foreignKey' => 'orgc_id'
        )
    );

    private $__clusterCache = array();

    public $hasMany = array(
        'GalaxyElement' => array('dependent' => true),
    //  'GalaxyReference'
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (!isset($this->data['GalaxyCluster']['description'])) {
            $this->data['GalaxyCluster']['description'] = '';
        }
        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (isset($results[$k]['GalaxyCluster']['authors'])) {
                $results[$k]['GalaxyCluster']['authors'] = json_decode($results[$k]['GalaxyCluster']['authors'], true);
            }
        }
        return $results;
    }

    public function beforeDelete($cascade = true)
    {
        $this->GalaxyElement->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $this->id));
    }


    // receive a full galaxy and add all new clusters, update existing ones contained in the new galaxy, cull old clusters that are removed from the galaxy
    public function update($id, $galaxy)
    {
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
                $newCluster['collection_uuid'] = $newCluster['uuid'];
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
    public function getTags($galaxyType, $clusterValue = false, $user)
    {
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
    public function getCluster($name, $user)
    {
        if (isset($this->__clusterCache[$name])) {
            return $this->__clusterCache[$name];
        }
        $conditions = $this->buildConditions($user);
        if (is_numeric($name)) {
            $conditions['AND'] = array('GalaxyCluster.id' => $name);
        } else {
            $conditions['AND'] = array('LOWER(GalaxyCluster.tag_name)' => strtolower($name));
        }

        $cluster = $this->find('first', array(
            'conditions' => $conditions,
            'contain' => array('Galaxy', 'GalaxyElement')
        ));

        if (!empty($cluster)) {
            $cluster = $this->postprocess($cluster);
        }
        if (!empty($cluster) && $cluster['GalaxyCluster']['default']) { // only cache default clusters
            $this->__clusterCache[$name] = $cluster;
        }
        return $cluster;
    }

    public function getClusters($names, $user, $postProcess=true)
    {
        $conditions = $this->buildConditions($user);
        if (count(array_filter($names, 'is_numeric' )) === count($names)) { // all elements are numeric
            $conditions['AND'] = array('GalaxyCluster.id' => $names);
        } else {
            $names = array_map('strtolower', $names);
            $conditions['AND'] = array('LOWER(GalaxyCluster.tag_name)' => $names);
        }

        $clusters = $this->find('all', array(
            'conditions' => $conditions,
            'contain' => array('Galaxy', 'GalaxyElement')
        ));

        if (!empty($clusters) && $postProcess) {
            $clusters = $this->postprocess($clusters);
        }

        return $clusters;
    }

    public function buildConditions($user)
    {
        $this->Event = ClassRegistry::init('Event');
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->Event->cacheSgids($user, true);
            $conditions['AND']['OR'] = array(
                'GalaxyCluster.org_id' => $user['org_id'],
                array(
                    'AND' => array(
                        'GalaxyCluster.distribution >' => 0,
                        'GalaxyCluster.distribution <' => 4
                    ),
                ),
                array(
                    'AND' => array(
                        'GalaxyCluster.sharing_group_id' => $sgids,
                        'GalaxyCluster.distribution' => 4
                    )
                )
            );
        }
        return $conditions;
    }

    // very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
    // options:
    //     fields
    //     contain
    //     conditions
    //     order
    //     group
    public function fetchGalaxyClusters($user, $options, $full=false)
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
            'recursive' => -1
        );
        $params['contain'] = $options['contain'];
        if ($full && !in_array('GalaxyElement', $params['contain'])) {
            $params['contain'][] = 'GalaxyElement';
        }
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
        }
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (isset($options['group'])) {
            $params['group'] = empty($options['group']) ? $options['group'] : false;
        }
        $galaxClusters = $this->find('all', $params);
        // foreach($galaxies as $k => $galaxy) {
        //     $galaxies[$k] = $this->Org->attachOrgs($galaxy, array('id', 'name', 'uuid', 'local'), 'Galaxy');
        // }
        return $galaxClusters;
    }

    /**
     * @param array $events
     * @param bool $replace
     * @return array
     */
    public function attachClustersToEventIndex($user, array $events, $replace = false)
    {
        $clusterTagNames = array();
        foreach ($events as $event) {
            foreach ($event['EventTag'] as $k2 => $eventTag) {
                if (substr($eventTag['Tag']['name'], 0, strlen('misp-galaxy:')) === 'misp-galaxy:') {
                    $clusterTagNames[] = $eventTag['Tag']['name'];
                }
            }
        }

        $clusters = $this->getClusters($clusterTagNames, $user, false);

        $clustersByTagName = array();
        foreach ($clusters as $cluster) {
            $clustersByTagName[strtolower($cluster['GalaxyCluster']['tag_name'])] = $cluster;
        }

        foreach ($events as $k => $event) {
            foreach ($event['EventTag'] as $k2 => $eventTag) {
                $tagName = strtolower($eventTag['Tag']['name']);
                if (isset($clustersByTagName[$tagName])) {
                    $cluster = $this->postprocess($clustersByTagName[$tagName], $eventTag['Tag']['id']);
                    $cluster['GalaxyCluster']['tag_id'] = $eventTag['Tag']['id'];
                    $cluster['GalaxyCluster']['local'] = $eventTag['local'];
                    $events[$k]['GalaxyCluster'][] = $cluster['GalaxyCluster'];
                    if ($replace) {
                        unset($events[$k]['EventTag'][$k2]);
                    }
                }
            }
        }
        return $events;
    }

    /**
     * @param array $cluster
     * @param int|null $tagId
     * @return array
     */
    private function postprocess(array $cluster, $tagId = null)
    {
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
        $cluster['GalaxyCluster']['meta'] = $elements;

        if ($tagId) {
            $cluster['GalaxyCluster']['tag_id'] = $tagId;
        } else {
            $this->Tag = ClassRegistry::init('Tag');
            $tag_id = $this->Tag->find(
                'first',
                array(
                    'conditions' => array(
                        'LOWER(Tag.name)' => strtolower($cluster['GalaxyCluster']['tag_name'])
                    ),
                    'recursive' => -1,
                    'fields' => array('Tag.id')
                )
            );
            if (!empty($tag_id)) {
                $cluster['GalaxyCluster']['tag_id'] = $tag_id['Tag']['id'];
            }
        }

        return $cluster;
    }

    public function getClusterTagsFromMeta($galaxyElements, $user)
    {
        // AND operator between cluster metas
        $tmpResults = array();
        foreach ($galaxyElements as $galaxyElementKey => $galaxyElementValue) {
            $tmpResults[] = array_values($this->GalaxyElement->find('list', array(
                'conditions' => array(
                    'key' => $galaxyElementKey,
                    'value' => $galaxyElementValue,
                ),
                'fields' => array('galaxy_cluster_id'),
                'recursive' => -1
            )));
        }
        $clusterTags = array();
        if (!empty($tmpResults)) {
            // Get all Clusters matching all conditions
            $matchingClusters = $tmpResults[0];
            array_shift($tmpResults);
            foreach ($tmpResults as $tmpResult) {
                $matchingClusters = array_intersect($matchingClusters, $tmpResult);
            }
    
            $clusterTags = $this->find('list', array(
                'conditions' => array('id' => $matchingClusters),
                'fields' => array('GalaxyCluster.tag_name'),
                'recursive' => -1
            ));
            // TODO: Apply ACL
        }
        return array_values($clusterTags);
    }
}
