<?php
App::uses('AppModel', 'Model');
class Galaxy extends AppModel
{
    public $useTable = 'galaxies';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'),
        'Containable',
    );

    public $validate = array(
    );

    public $hasMany = array(
        'GalaxyCluster' => array('dependent' => true)
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (isset($this->data['Galaxy']['kill_chain_order'])) {
            $json = json_encode($this->data['Galaxy']['kill_chain_order']);
            if ($json !== null) {
                $this->data['Galaxy']['kill_chain_order'] = $json;
            } else {
                unset($this->data['Galaxy']['kill_chain_order']);
            }
        }
        return true;
    }

    public function beforeDelete($cascade = true)
    {
        $this->GalaxyCluster->deleteAll(array('GalaxyCluster.galaxy_id' => $this->id));
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $v) {
            if (isset($v['Galaxy']['kill_chain_order']) && $v['Galaxy']['kill_chain_order'] !== '') {
                $results[$k]['Galaxy']['kill_chain_order'] = json_decode($v['Galaxy']['kill_chain_order'], true);
            } else {
                unset($results[$k]['Galaxy']['kill_chain_order']);
            }
        }
        return $results;
    }

    private function __load_galaxies($force = false)
    {
        $dir = new Folder(APP . 'files' . DS . 'misp-galaxy' . DS . 'galaxies');
        $files = $dir->find('.*\.json');
        $galaxies = array();
        foreach ($files as $file) {
            $file = new File($dir->pwd() . DS . $file);
            $galaxies[] = json_decode($file->read(), true);
            $file->close();
        }
        $galaxyTypes = array();
        foreach ($galaxies as $i => $galaxy) {
            $galaxyTypes[$galaxy['type']] = $galaxy['type'];
        }
        $temp = $this->find('all', array(
            'fields' => array('uuid', 'version', 'id', 'icon'),
            'recursive' => -1
        ));
        $existingGalaxies = array();
        foreach ($temp as $v) {
            $existingGalaxies[$v['Galaxy']['uuid']] = $v['Galaxy'];
        }
        foreach ($galaxies as $k => $galaxy) {
            if (isset($existingGalaxies[$galaxy['uuid']])) {
                if (
                    $force ||
                    $existingGalaxies[$galaxy['uuid']]['version'] < $galaxy['version'] ||
                    (!empty($galaxy['icon']) && ($existingGalaxies[$galaxy['uuid']]['icon'] != $galaxy['icon']))
                ) {
                    $galaxy['id'] = $existingGalaxies[$galaxy['uuid']]['id'];
                    $this->save($galaxy);
                }
            } else {
                $this->create();
                $this->save($galaxy);
            }
        }
        return $this->find('list', array('recursive' => -1, 'fields' => array('type', 'id')));
    }

    private function __update_prepare_template(array $cluster_package, array $galaxies)
    {
        return [
            'source' => isset($cluster_package['source']) ? $cluster_package['source'] : '',
            'authors' => json_encode(isset($cluster_package['authors']) ? $cluster_package['authors'] : array(), true),
            'collection_uuid' => isset($cluster_package['uuid']) ? $cluster_package['uuid'] : '',
            'galaxy_id' => $galaxies[$cluster_package['type']],
            'type' => $cluster_package['type'],
            'tag_name' => 'misp-galaxy:' . $cluster_package['type'] . '="'
        ];
    }

    private function __getPreExistingClusters(array $galaxies, array $cluster_package)
    {
        $temp = $this->GalaxyCluster->find('all', array(
            'conditions' => array(
                'GalaxyCluster.galaxy_id' => $galaxies[$cluster_package['type']]
            ),
            'recursive' => -1,
            'fields' => array('version', 'id', 'value', 'uuid')
        ));
        $existingClusters = [];
        foreach ($temp as $k => $v) {
            $existingClusters[$v['GalaxyCluster']['value']] = $v;
        }
        return $existingClusters;
    }

    private function __deleteOutdated(bool $force, array $cluster_package, array $existingClusters)
    {
        // Delete all existing outdated clusters
        $cluster_ids_to_delete = array();
        $cluster_uuids_to_delete = array();
        foreach ($cluster_package['values'] as $k => $cluster) {
            if (empty($cluster['value'])) {
                continue;
            }
            if (isset($cluster['version'])) {
            } elseif (!empty($cluster_package['version'])) {
                $cluster_package['values'][$k]['version'] = $cluster_package['version'];
            } else {
                $cluster_package['values'][$k]['version'] = 0;
            }
            if (!empty($existingClusters[$cluster['value']])) {
                if ($force || $existingClusters[$cluster['value']]['GalaxyCluster']['version'] < $cluster_package['values'][$k]['version']) {
                    $cluster_ids_to_delete[] = $existingClusters[$cluster['value']]['GalaxyCluster']['id'];
                    $cluster_uuids_to_delete[] = $existingClusters[$cluster['value']]['GalaxyCluster']['uuid'];
                } else {
                    unset($cluster_package['values'][$k]);
                }
            }
        }
        if (!empty($cluster_ids_to_delete)) {
            $this->GalaxyCluster->GalaxyElement->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $cluster_ids_to_delete), false, false);
            $this->GalaxyCluster->GalaxyClusterRelation->deleteRelations(array('GalaxyClusterRelation.galaxy_cluster_uuid' => $cluster_uuids_to_delete));
            $this->GalaxyCluster->deleteAll(array('GalaxyCluster.id' => $cluster_ids_to_delete), false, false);
        }
        return $cluster_package;
    }

    private function __createClusters($cluster_package, $template)
    {
        $relations = [];
        $elements = [];
        $saved_tag_names = [];
        $this->GalaxyCluster->bulkEntry = true;
        foreach ($cluster_package['values'] as $cluster) {
            if (empty($cluster['version'])) {
                $cluster['version'] = 1;
            }
            $template['version'] = $cluster['version'];
            $this->GalaxyCluster->create();
            $cluster_to_save = $template;
            if (isset($cluster['description'])) {
                $cluster_to_save['description'] = $cluster['description'];
                unset($cluster['description']);
            }
            $cluster_to_save['value'] = $cluster['value'];
            $cluster_to_save['tag_name'] = $cluster_to_save['tag_name'] . $cluster['value'] . '"';
            if (!empty($cluster['uuid'])) {
                $cluster_to_save['uuid'] = $cluster['uuid'];
            }
            unset($cluster['value']);
            if (empty($cluster_to_save['description'])) {
                $cluster_to_save['description'] = '';
            }
            $cluster_to_save['distribution'] = 3;
            $cluster_to_save['default'] = true;
            $cluster_to_save['published'] = false;
            $cluster_to_save['org_id'] = 0;
            $cluster_to_save['orgc_id'] = 0;
            $result = $this->GalaxyCluster->save($cluster_to_save, false);
            $galaxyClusterId = $this->GalaxyCluster->id;
            if (isset($cluster['meta'])) {
                foreach ($cluster['meta'] as $key => $value) {
                    if (!is_array($value)) {
                        $value = [$value];
                    }
                    foreach ($value as $v) {
                        if (is_array($v)) {
                            $this->Log = ClassRegistry::init('Log');
                            $this->Log->create();
                            $this->Log->save(array(
                                'org' => 'SYSTEM',
                                'model' => 'Galaxy',
                                'model_id' => 0,
                                'email' => 0,
                                'action' => 'error',
                                'title' => sprintf('Found a malformed galaxy cluster (%s) during the update, skipping. Reason: Malformed meta field, embedded array found.', $cluster['uuid']),
                                'change' => ''
                            ));
                        } else {
                            $elements[] = array(
                                $galaxyClusterId,
                                $key,
                                strval($v)
                            );
                        }
                    }
                }
            }
            if (isset($cluster['related'])) {
                foreach ($cluster['related'] as $key => $relation) {
                    $relations[] = [
                        'galaxy_cluster_id' => $galaxyClusterId,
                        'galaxy_cluster_uuid' => $cluster['uuid'],
                        'referenced_galaxy_cluster_uuid' => $relation['dest-uuid'],
                        'referenced_galaxy_cluster_type' => $relation['type'],
                        'default' => true,
                        'distribution' => 3,
                        'tags' => !empty($relation['tags']) ? $relation['tags'] : []
                    ];
                }
            }
        }
        return [$elements, $relations];
    }

    public function update($force = false)
    {
        $galaxies = $this->__load_galaxies($force);
        $dir = new Folder(APP . 'files' . DS . 'misp-galaxy' . DS . 'clusters');
        $files = $dir->find('.*\.json');
        $force = (bool)$force;
        foreach ($files as $file) {
            $file = new File($dir->pwd() . DS . $file);
            $cluster_package = json_decode($file->read(), true);
            $file->close();
            if (!isset($galaxies[$cluster_package['type']])) {
                continue;
            }
            $template = $this->__update_prepare_template($cluster_package, $galaxies);
            $elements = [];
            $existingClusters = $this->__getPreExistingClusters($galaxies, $cluster_package);
            $cluster_package = $this->__deleteOutdated($force, $cluster_package, $existingClusters);

            // create all clusters
            list($elements, $relations) = $this->__createClusters($cluster_package, $template);
            $db = $this->getDataSource();
            $fields = array('galaxy_cluster_id', 'key', 'value');
            if (!empty($elements)) {
                $db = $this->getDataSource();
                $fields = array('galaxy_cluster_id', 'key', 'value');
                $db->insertMulti('galaxy_elements', $fields, $elements);
            }
            if (!empty($relations)) {
                $this->GalaxyCluster->GalaxyClusterRelation->bulkSaveRelations($relations);
            }
        }
        $this->GalaxyCluster->generateMissingRelations();
        return true;
    }

    /**
     * Capture the Galaxy
     *
     * @param $user
     * @param array $user
     * @param array $galaxy The galaxy to be captured
     * @return array the captured galaxy
     */
    public function captureGalaxy(array $user, array $galaxy)
    {
        if (empty($galaxy['uuid'])) {
            return false;
        }
        $existingGalaxy = $this->find('first', array(
            'recursive' => -1,
            'conditions' => array('Galaxy.uuid' => $galaxy['uuid'])
        ));
        if (empty($existingGalaxy)) {
            if ($user['Role']['perm_site_admin'] || $user['Role']['perm_galaxy_editor']) {
                $this->create();
                unset($galaxy['id']);
                $this->save($galaxy);
                $existingGalaxy = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Galaxy.id' => $this->id)
                ));
            } else {
                return false;
            }
        }
        return $existingGalaxy;
    }

    /**
     * Import all clusters into the Galaxy they are shipped with, creating the galaxy if not existant.
     *
     * This function is meant to be used with manual import or push from remote instance
     * @param $user
     * @param array $clusters clusters to import
     * @return array The import result with errors if any
     */
    public function importGalaxyAndClusters($user, array $clusters)
    {
        $results = array('success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 0, 'errors' => array());
        foreach ($clusters as $k => $cluster) {
            $conditions = array();
            if (!empty($cluster['GalaxyCluster']['Galaxy'])) {
                $existingGalaxy = $this->captureGalaxy($user, $cluster['GalaxyCluster']['Galaxy']);
            } elseif (!empty($cluster['GalaxyCluster']['type'])) {
                $existingGalaxy = $this->find('first', array(
                    'recursive' => -1,
                    'fields' => array('id', 'version'),
                    'conditions' => array('Galaxy.type' => $cluster['GalaxyCluster']['type']),
                ));
                if (empty($existingGalaxy)) { // We don't have enough info to create the galaxy
                    $results['failed']++;
                    $results['errors'][] = __('Galaxy not found');
                    continue;
                }
            } else { // We don't have the galaxy nor can create it
                $results['failed']++;
                $results['errors'][] = __('Galaxy not found');
                continue;
            }
            $cluster['GalaxyCluster']['galaxy_id'] = $existingGalaxy['Galaxy']['id'];
            $cluster['GalaxyCluster']['locked'] = true;
            $saveResult = $this->GalaxyCluster->captureCluster($user, $cluster, $fromPull=false);
            if (empty($saveResult['errors'])) {
                $results['imported'] += $saveResult['imported'];
            } else {
                $results['ignored'] += $saveResult['ignored'];
                $results['failed'] += $saveResult['failed'];
                $results['errors'] = array_merge($results['errors'], $saveResult['errors']);
            }
        }
        $results['success'] = !($results['failed'] > 0 && $results['imported'] == 0);
        return $results;
    }

    public function attachCluster($user, $target_type, $target_id, $cluster_id, $local = false)
    {
        $connectorModel = Inflector::camelize($target_type) . 'Tag';
        if ($local == 1 || $local === true) {
            $local = 1;
        } else {
            $local = 0;
        }
        $cluster = $this->GalaxyCluster->fetchGalaxyClusters($user, array(
            'first' => true,
            'conditions' => array('id' => $cluster_id),
            'fields' => array('tag_name', 'id', 'value'),
        ), $full=false);
        if (empty($cluster)) {
            throw new NotFoundException(__('Invalid Galaxy cluster'));
        }
        $this->Tag = ClassRegistry::init('Tag');
        if ($target_type === 'event') {
            $target = $this->Tag->EventTag->Event->fetchEvent($user, array('eventid' => $target_id, 'metadata' => 1));
        } elseif ($target_type === 'attribute') {
            $target = $this->Tag->AttributeTag->Attribute->fetchAttributes($user, array('conditions' => array('Attribute.id' => $target_id), 'flatten' => 1));
        } elseif ($target_type === 'tag_collection') {
            $target = $this->Tag->TagCollectionTag->TagCollection->fetchTagCollection($user, array('conditions' => array('TagCollection.id' => $target_id)));
        }
        if (empty($target)) {
            throw new NotFoundException(__('Invalid %s.', $target_type));
        }
        $target = $target[0];
        $tag_id = $this->Tag->captureTag(array('name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1), $user, true);
        $existingTag = $this->Tag->$connectorModel->find('first', array('conditions' => array($target_type . '_id' => $target_id, 'tag_id' => $tag_id)));
        if (!empty($existingTag)) {
            return 'Cluster already attached.';
        }
        $this->Tag->$connectorModel->create();
        $toSave = array($target_type . '_id' => $target_id, 'tag_id' => $tag_id, 'local' => $local);
        if ($target_type === 'attribute') {
            $event = $this->Tag->EventTag->Event->find('first', array(
                'conditions' => array(
                    'Event.id' => $target['Attribute']['event_id']
                ),
                'recursive' => -1
            ));
            $toSave['event_id'] = $target['Attribute']['event_id'];
        }
        $result = $this->Tag->$connectorModel->save($toSave);
        if ($result) {
            if ($target_type !== 'tag_collection') {
                $date = new DateTime();
                if ($target_type === 'event') {
                    $event = $target;
                } else if ($target_type === 'attribute') {
                    $target['Attribute']['timestamp'] = $date->getTimestamp();
                    $this->Tag->AttributeTag->Attribute->save($target);
                    if (!empty($target['Attribute']['object_id'])) {
                        $container_object = $this->Tag->AttributeTag->Attribute->Object->find('first', [
                            'recursive' => -1,
                            'conditions' => ['id' => $target['Attribute']['object_id']]
                        ]);
                        $container_object['Object']['timestamp'] = $date->getTimestamp();
                        $this->Tag->AttributeTag->Attribute->Object->save($container_object);
                    }
                }
                $this->Tag->EventTag->Event->insertLock($user, $event['Event']['id']);
                $event['Event']['published'] = 0;
                $event['Event']['timestamp'] = $date->getTimestamp();
                $this->Tag->EventTag->Event->save($event);
            }
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                'org' => $user['Organisation']['name'],
                'model' => ucfirst($target_type),
                'model_id' => $target_id,
                'email' => $user['email'],
                'action' => 'galaxy',
                'title' => 'Attached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') to ' . $target_type . ' (' . $target_id . ')',
                'change' => ''
            ));
            return 'Cluster attached.';
        }
        return 'Could not attach the cluster';
    }

    public function detachCluster($user, $target_type, $target_id, $cluster_id)
    {
        $cluster = $this->GalaxyCluster->find('first', array(
            'recursive' => -1,
            'conditions' => array('id' => $cluster_id),
            'fields' => array('tag_name', 'id', 'value')
        ));
        $this->Tag = ClassRegistry::init('Tag');
        if ($target_type === 'event') {
            $target = $this->Tag->EventTag->Event->fetchEvent($user, array('eventid' => $target_id, 'metadata' => 1));
            if (empty($target)) {
                throw new NotFoundException(__('Invalid %s.', $target_type));
            }
            $target = $target[0];
            $event = $target;
            $event_id = $target['Event']['id'];
            $org_id = $event['Event']['org_id'];
            $orgc_id = $event['Event']['orgc_id'];
        } elseif ($target_type === 'attribute') {
            $target = $this->Tag->AttributeTag->Attribute->fetchAttributes($user, array('conditions' => array('Attribute.id' => $target_id), 'flatten' => 1));
            if (empty($target)) {
                throw new NotFoundException(__('Invalid %s.', $target_type));
            }
            $target = $target[0];
            $event_id = $target['Attribute']['event_id'];
            $event = $this->Tag->EventTag->Event->fetchEvent($user, array('eventid' => $event_id, 'metadata' => 1));
            if (empty($event)) {
                throw new NotFoundException(__('Invalid event'));
            }
            $event = $event[0];
            $org_id = $event['Event']['org_id'];
            $orgc_id = $event['Event']['org_id'];
        } elseif ($target_type === 'tag_collection') {
            $target = $this->Tag->TagCollectionTag->TagCollection->fetchTagCollection($user, array('conditions' => array('TagCollection.id' => $target_id)));
            if (empty($target)) {
                throw new NotFoundException(__('Invalid %s.', $target_type));
            }
            $target = $target[0];
            $org_id = $target['org_id'];
            $orgc_id = $org_id;
        }

        if (!$user['Role']['perm_site_admin'] && !$user['Role']['perm_sync']) {
            if (
                ($scope === 'tag_collection' && !$user['Role']['perm_tag_editor']) ||
                ($scope !== 'tag_collection' && !$user['Role']['perm_tagger']) ||
                ($user['org_id'] !== $org_id && $user['org_id'] !== $orgc_id)
            ) {
                throw new MethodNotAllowedException('Invalid ' . Inflector::humanize($targe_type) . '.');
            }
        }

        $tag_id = $this->Tag->captureTag(array('name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1), $user);

        if ($target_type == 'attribute') {
            $existingTargetTag = $this->Tag->AttributeTag->find('first', array(
                'conditions' => array('AttributeTag.tag_id' => $tag_id, 'AttributeTag.attribute_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($target_type == 'event') {
            $existingTargetTag = $this->Tag->EventTag->find('first', array(
                'conditions' => array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($target_type == 'tag_collection') {
            $existingTargetTag = $this->Tag->TagCollectionTag->TagCollection->find('first', array(
                'conditions' => array('tag_id' => $tag_id, 'tag_collection_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        }

        if (empty($existingTargetTag)) {
            return 'Cluster not attached.';
        } else {
            if ($target_type == 'event') {
                $result = $this->Tag->EventTag->delete($existingTargetTag['EventTag']['id']);
            } elseif ($target_type == 'attribute') {
                $result = $this->Tag->AttributeTag->delete($existingTargetTag['AttributeTag']['id']);
            } elseif ($target_type == 'tag_collection') {
                $result = $this->Tag->TagCollectionTag->delete($existingTargetTag['TagCollectionTag']['id']);
            }

            if ($result) {
                if ($target_type !== 'tag_collection') {
                    $this->Tag->EventTag->Event->insertLock($user, $event['Event']['id']);
                    $event['Event']['published'] = 0;
                    $date = new DateTime();
                    $event['Event']['timestamp'] = $date->getTimestamp();
                    $this->Tag->EventTag->Event->save($event);
                }
                $this->Log = ClassRegistry::init('Log');
                $this->Log->create();
                $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => ucfirst($target_type),
                    'model_id' => $target_id,
                    'email' => $user['email'],
                    'action' => 'galaxy',
                    'title' => 'Detached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') to ' . $target_type . ' (' . $target_id . ')',
                    'change' => ''
                ));
                return 'Cluster detached';
            } else {
                return 'Could not detach cluster';
            }
        }
    }

    public function getMitreAttackGalaxyId($type="mitre-attack-pattern", $namespace="mitre-attack")
    {
        $galaxy = $this->find('first', array(
                'recursive' => -1,
                'fields' => array('MAX(Galaxy.version) as latest_version', 'id'),
                'conditions' => array(
                    'Galaxy.type' => $type,
                    'Galaxy.namespace' => $namespace
                ),
                'group' => array('name', 'id')
        ));
        return empty($galaxy) ? 0 : $galaxy['Galaxy']['id'];
    }

    public function getAllowedMatrixGalaxies()
    {
        $conditions = array(
            'NOT' => array(
                'kill_chain_order' => ''
            )
        );
        $galaxies = $this->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
        ));
        return $galaxies;
    }

    public function getMatrix($galaxy_id, $scores=array())
    {
        $conditions = array('Galaxy.id' => $galaxy_id);
        $contains = array(
            'GalaxyCluster' => array('GalaxyElement'),
        );

        $galaxy = $this->find('first', array(
                'recursive' => -1,
                'contain' => $contains,
                'conditions' => $conditions,
        ));

        $mispUUID = Configure::read('MISP')['uuid'];

        if (!isset($galaxy['Galaxy']['kill_chain_order'])) {
            throw new MethodNotAllowedException(__("Galaxy cannot be represented as a matrix"));
        }
        $matrixData = array(
            'killChain' => $galaxy['Galaxy']['kill_chain_order'],
            'tabs' => array(),
            'matrixTags' => array(),
            'instance-uuid' => $mispUUID,
            'galaxy' => $galaxy['Galaxy']
        );

        $clusters = $galaxy['GalaxyCluster'];
        $cols = array();

        foreach ($clusters as $cluster) {
            if (empty($cluster['GalaxyElement'])) {
                continue;
            }

            $toBeAdded = false;
            $clusterType = $cluster['type'];
            $galaxyElements = $cluster['GalaxyElement'];
            foreach ($galaxyElements as $element) {
                // add cluster if kill_chain is present
                if ($element['key'] == 'kill_chain') {
                    $kc = explode(":", $element['value']);
                    $galaxyType = $kc[0];
                    $kc = $kc[1];
                    $cols[$galaxyType][$kc][] = $cluster;
                    $toBeAdded = true;
                }
                if ($element['key'] == 'external_id') {
                    $cluster['external_id'] = $element['value'];
                }
                if ($toBeAdded) {
                    $matrixData['matrixTags'][$cluster['tag_name']] = 1;
                }
            }
        }
        $matrixData['tabs'] = $cols;

        $this->sortMatrixByScore($matrixData['tabs'], $scores);
        // #FIXME temporary fix: retrieve tag name of deprecated mitre galaxies (for the stats)
        if ($galaxy['Galaxy']['id'] == $this->getMitreAttackGalaxyId()) {
            $names = array('Enterprise Attack - Attack Pattern', 'Pre Attack - Attack Pattern', 'Mobile Attack - Attack Pattern');
            $tag_names = array();
            $gals = $this->find('all', array(
                    'recursive' => -1,
                    'contain' => array('GalaxyCluster.tag_name'),
                    'conditions' => array('Galaxy.name' => $names)
            ));
            foreach ($gals as $gal => $temp) {
                foreach ($temp['GalaxyCluster'] as $value) {
                    $matrixData['matrixTags'][$value['tag_name']] = 1;
                }
            }
        }
        // end FIXME

        $matrixData['matrixTags'] = array_keys($matrixData['matrixTags']);
        return $matrixData;
    }

    public function sortMatrixByScore(&$tabs, $scores)
    {
        foreach (array_keys($tabs) as $i) {
            foreach (array_keys($tabs[$i]) as $j) {
                // major ordering based on score, minor based on alphabetical
                usort($tabs[$i][$j], function ($a, $b) use ($scores) {
                    if ($a['tag_name'] == $b['tag_name']) {
                        return 0;
                    }
                    if (isset($scores[$a['tag_name']]) && isset($scores[$b['tag_name']])) {
                        if ($scores[$a['tag_name']] < $scores[$b['tag_name']]) {
                            $ret = 1;
                        } elseif ($scores[$a['tag_name']] == $scores[$b['tag_name']]) {
                            $ret = strcmp($a['value'], $b['value']);
                        } else {
                            $ret = -1;
                        }
                    } elseif (isset($scores[$a['tag_name']])) {
                        $ret = -1;
                    } elseif (isset($scores[$b['tag_name']])) {
                        $ret = 1;
                    } else { // none are set
                        $ret = strcmp($a['value'], $b['value']);
                    }
                    return $ret;
                });
            }
        }
    }

    /**
     * generateForkTree
     *
     * @param  mixed $clusters The accessible cluster for the user to be arranged into a fork tree
     * @param  mixed $galaxy The galaxy for which the fork tree is generated
     * @param  bool $pruneRootLeaves Should the nonforked clusters be removed from the tree
     * @return array The generated fork tree where the children of a node are contained in the `children` key
     */
    public function generateForkTree(array $clusters, array $galaxy, $pruneRootLeaves=true)
    {
        $tree = array();
        $lookup = array();
        $lastNodeAdded = array();
        // generate the lookup table used to immediatly get the correct cluster
        foreach ($clusters as $i => $cluster) {
            $clusters[$i]['children'] = array();
            $lookup[$cluster['GalaxyCluster']['id']] = &$clusters[$i];
        }
        foreach ($clusters as $i => $cluster) {
            if (!empty($cluster['GalaxyCluster']['extended_from'])) {
                $parent = $cluster['GalaxyCluster']['extended_from'];
                $clusterVersion = $cluster['GalaxyCluster']['extends_version'];
                $parentVersion = $lookup[$parent['GalaxyCluster']['id']]['GalaxyCluster']['version'];
                if ($clusterVersion == $parentVersion) {
                    $lookup[$parent['GalaxyCluster']['id']]['children'][] = &$clusters[$i];
                } else {
                    // version differs, insert version node between child and parent
                    $lastVersionNode = array(
                        'isVersion' => true,
                        'isLast' => true,
                        'version' => $parentVersion,
                        'parentUuid' => $parent['GalaxyCluster']['uuid'],
                        'children' => array()
                    );
                    $versionNode = array(
                        'isVersion' => true,
                        'isLast' => false,
                        'version' => $clusterVersion,
                        'parentUuid' => $parent['GalaxyCluster']['uuid'],
                        'children' => array(&$clusters[$i])
                    );
                    $lookup[$parent['GalaxyCluster']['id']]['children'][] = $versionNode;
                    if (!isset($lastNodeAdded[$parent['GalaxyCluster']['id']])) {
                        $lookup[$parent['GalaxyCluster']['id']]['children'][] = $lastVersionNode;
                        $lastNodeAdded[$parent['GalaxyCluster']['id']] = true;
                    }
                }
            } else {
                $tree[] = &$clusters[$i];
            }
        }

        if ($pruneRootLeaves) {
            foreach ($tree as $i => $node) {
                if (empty($node['children'])) {
                    unset($tree[$i]);
                }
            }
        }

        $tree = array(array(
            'Galaxy' => $galaxy['Galaxy'],
            'children' => array_values($tree)
        ));
        return $tree;
    }

    /**
     * convertToMISPGalaxyFormat
     *
     * @param  array $galaxy
     * @param  array $clusters
     * @return array the converted clusters into the misp-galaxy format
     *
     * Special cases:
     *  - authors: (since all clusters have their own, takes all of them)
     *  - version: Takes the higher version number of all clusters
     *  - uuid: Is actually the collection_uuid. Takes the last one
     *  - source (since all clusters have their own, takes the last one)
     *  - category (not saved in MISP nor used)
     *  - description (not used as the description in the galaxy.json is used instead)
     */
    public function convertToMISPGalaxyFormat($galaxy, $clusters)
    {
        $converted = [];
        $converted['name'] = $galaxy['Galaxy']['name'];
        $converted['type'] = $galaxy['Galaxy']['type'];
        $converted['authors'] = [];
        $converted['version'] = 0;
        $values = [];
        $fieldsToSave = ['description', 'uuid', 'value', 'extends_uuid', 'extends_version'];
        foreach ($clusters as $i => $cluster) {
            foreach ($fieldsToSave as $field) {
                $values[$i][$field] = $cluster['GalaxyCluster'][$field];
            }
            $converted['uuid'] = $cluster['GalaxyCluster']['collection_uuid'];
            $converted['source'] = $cluster['GalaxyCluster']['source'];
            if (!empty($cluster['GalaxyCluster']['authors'])) {
                foreach ($cluster['GalaxyCluster']['authors'] as $author) {
                    if (!is_null($author) && $author != 'null') {
                        $converted['authors'][$author] = $author;
                    }
                }
            }
            $converted['version'] = $converted['version'] > $cluster['GalaxyCluster']['version'];
            foreach ($cluster['GalaxyCluster']['GalaxyElement'] as $element) {
                if (isset($values[$i]['meta'][$element['key']])) {
                    if (is_array($values[$i]['meta'][$element['key']])) {
                        $values[$i]['meta'][$element['key']][] = $element['value'];
                    } else {
                        $values[$i]['meta'][$element['key']] = [$values[$i]['meta'][$element['key']], $element['value']];
                    }
                } else {
                    $values[$i]['meta'][$element['key']] = $element['value'];
                }
            }
            foreach ($cluster['GalaxyCluster']['GalaxyClusterRelation'] as $j => $relation) {
                $values[$i]['related'][$j] = [
                    'dest-uuid' => $relation['referenced_galaxy_cluster_uuid'],
                    'type' => $relation['referenced_galaxy_cluster_type'],
                ];
                if (!empty($relation['Tag'])) {
                    foreach ($relation['Tag'] as $tag) {
                        $values[$i]['related'][$j]['tags'][] = $tag['name'];
                    }
                }
            }
        }
        $converted['authors'] = array_values($converted['authors']);
        $converted['values'] = $values;
        return $converted;
    }
}
