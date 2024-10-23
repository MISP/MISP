<?php
App::uses('AppModel', 'Model');

/**
 * @property GalaxyCluster $GalaxyCluster
 * @property Galaxy $Galaxy
 */
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

    public $hasMany = array(
        'GalaxyCluster' => array('dependent' => true)
    );

    public $belongsTo = [
        'Org' => [
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        ],
        'Orgc' => [
            'className' => 'Organisation',
            'foreignKey' => 'orgc_id'
        ],
    ];

    public $validate = array(
        'kill_chain_order' => array(
            'rule' => 'valueIsJson',
            'message' => 'The provided Kill Chain Order is not a valid json format',
            'required' => false,
        ),
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (isset($this->data['Galaxy']['kill_chain_order'])) {
            if (is_array($this->data['Galaxy']['kill_chain_order'])) {
                $json = json_encode($this->data['Galaxy']['kill_chain_order']);
            } else {
                $json = $this->data['Galaxy']['kill_chain_order'];
            }
            if ($json !== null) {
                $this->data['Galaxy']['kill_chain_order'] = $json;
            } else {
                unset($this->data['Galaxy']['kill_chain_order']);
            }
            
        }
        return true;
    }

    public function beforeSave($options = [])
    {
        parent::beforeSave($options);
        if (empty($this->data['Galaxy']['created'])) {
            $this->data['Galaxy']['created'] = (new DateTime())->format('Y-m-d H:i:s');
            $this->data['Galaxy']['created'] = (new DateTime($this->data['Galaxy']['created'], new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        }
        if (empty($this->data['Galaxy']['modified'])) {
            $this->data['Galaxy']['modified'] = (new DateTime())->format('Y-m-d H:i:s');
            $this->data['Galaxy']['modified'] = (new DateTime($this->data['Galaxy']['modified'], new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
        }
        if (empty($this->data['Galaxy']['uuid'])) {
            $this->data['Galaxy']['uuid'] = CakeText::uuid();
        }
        if (empty($this->data['Galaxy']['type'])) {
            $this->data['Galaxy']['type'] =  $this->data['Galaxy']['uuid'];
        }
        if (empty($this->data['Galaxy']['version'])) {
            $date = new DateTime();
            $this->data['Galaxy']['version'] = $date->getTimestamp();
        }

        if (!isset($this->data['Galaxy']['default'])) {
            $this->data['Galaxy']['default'] = false;
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
            if (isset($v['Galaxy']['org_id']) && $v['Galaxy']['org_id'] == 0) {
                if (isset($results[$k]['Org'])) {
                    $results[$k]['Org'] = Organisation::GENERIC_MISP_ORGANISATION;
                }
            }
            if (isset($v['Galaxy']['orgc_id']) && $v['Galaxy']['orgc_id'] == 0) {
                if (isset($results[$k]['Orgc'])) {
                    $results[$k]['Orgc'] = Organisation::GENERIC_MISP_ORGANISATION;
                }
            }
        }
        return $results;
    }

    /**
     * @param bool $force
     * @return array Galaxy type => Galaxy ID
     * @throws Exception
     */
    private function __load_galaxies($force = false)
    {
        $files = new GlobIterator(APP . 'files' . DS . 'misp-galaxy' . DS . 'galaxies' . DS . '*.json');
        $galaxies = array();
        foreach ($files as $file) {
            $galaxies[] = FileAccessTool::readJsonFromFile($file->getPathname());
        }
        $existingGalaxies = $this->find('all', array(
            'fields' => array('uuid', 'version', 'id', 'icon'),
            'recursive' => -1
        ));
        $existingGalaxies = array_column(array_column($existingGalaxies, 'Galaxy'), null, 'uuid');
        foreach ($galaxies as $galaxy) {
            $galaxy['default'] = true;
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
            'authors' => json_encode(isset($cluster_package['authors']) ? $cluster_package['authors'] : array()),
            'collection_uuid' => isset($cluster_package['uuid']) ? $cluster_package['uuid'] : '',
            'galaxy_id' => $galaxies[$cluster_package['type']],
            'type' => $cluster_package['type'],
            'tag_name' => 'misp-galaxy:' . $cluster_package['type'] . '="'
        ];
    }

    /**
     * @param array $galaxies
     * @param array $cluster_package
     * @return array
     */
    private function __getPreExistingClusters(array $galaxies, array $cluster_package)
    {
        $temp = $this->GalaxyCluster->find('all', array(
            'conditions' => array(
                'GalaxyCluster.galaxy_id' => $galaxies[$cluster_package['type']]
            ),
            'recursive' => -1,
            'fields' => array('version', 'id', 'value', 'uuid')
        ));
        return array_column(array_column($temp, 'GalaxyCluster'), null, 'value');
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
            if (isset($existingClusters[$cluster['value']])) {
                $existing = $existingClusters[$cluster['value']];
                if ($force || $existing['version'] < $cluster_package['values'][$k]['version']) {
                    $cluster_ids_to_delete[] = $existing['id'];
                    $cluster_uuids_to_delete[] = $existing['uuid'];
                } else {
                    unset($cluster_package['values'][$k]);
                }
            }
        }
        if (!empty($cluster_ids_to_delete)) {
            $this->GalaxyCluster->GalaxyElement->deleteAll(array('GalaxyElement.galaxy_cluster_id' => $cluster_ids_to_delete), false);
            $this->GalaxyCluster->GalaxyClusterRelation->deleteAll(array('GalaxyClusterRelation.galaxy_cluster_uuid' => $cluster_uuids_to_delete));
            $this->GalaxyCluster->deleteAll(array('GalaxyCluster.id' => $cluster_ids_to_delete), false);
        }
        return $cluster_package;
    }

    private function __createClusters($cluster_package, $template)
    {
        $relations = [];
        $elements = [];
        $this->GalaxyCluster->bulkEntry = true;

        // Start transaction
        $this->getDataSource()->begin();

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
            // We are already in transaction
            $result = $this->GalaxyCluster->save($cluster_to_save, ['atomic' => false, 'validate' => false]);
            if (!$result) {
                $this->log("Could not save galaxy cluster with UUID {$cluster_to_save['uuid']}.");
                continue;
            }
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
                            $this->Log->saveOrFailSilently(array(
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
                                (string)$v
                            );
                        }
                    }
                }
            }
            if (isset($cluster['related'])) {
                foreach ($cluster['related'] as $relation) {
                    $relations[] = [
                        'galaxy_cluster_id' => $galaxyClusterId,
                        'galaxy_cluster_uuid' => $cluster['uuid'],
                        'referenced_galaxy_cluster_uuid' => $relation['dest-uuid'],
                        'referenced_galaxy_cluster_type' => $relation['type'],
                        'default' => true,
                        'distribution' => 3,
                        'tags' => $relation['tags'] ?? []
                    ];
                }
            }
        }

        // Commit transaction
        $this->getDataSource()->commit();

        return [$elements, $relations];
    }

    public function update($force = false)
    {
        $galaxies = $this->__load_galaxies($force);
        $files = new GlobIterator(APP . 'files' . DS . 'misp-galaxy' . DS . 'clusters' . DS . '*.json');
        $force = (bool)$force;
        $allRelations = [];
        foreach ($files as $file) {
            $cluster_package = FileAccessTool::readJsonFromFile($file->getPathname());
            if (!isset($galaxies[$cluster_package['type']])) {
                continue;
            }
            $template = $this->__update_prepare_template($cluster_package, $galaxies);
            $existingClusters = $this->__getPreExistingClusters($galaxies, $cluster_package);
            $cluster_package = $this->__deleteOutdated($force, $cluster_package, $existingClusters);

            // create all clusters
            list($elements, $relations) = $this->__createClusters($cluster_package, $template);
            if (!empty($elements)) {
                $db = $this->getDataSource();
                $fields = array('galaxy_cluster_id', 'key', 'value');
                $db->insertMulti('galaxy_elements', $fields, $elements);
            }
            array_push($allRelations, ...$relations);
        }
        // Save relation as last part when all clusters are created
        if (!empty($allRelations)) {
            $this->GalaxyCluster->GalaxyClusterRelation->bulkSaveRelations($allRelations);
        }
        // Probably unnecessary anymore
        $this->GalaxyCluster->generateMissingRelations();
        return true;
    }

    /**
     * Capture the Galaxy
     *
     * @param array $user
     * @param array $galaxy The galaxy to be captured
     * @return array|false the captured galaxy or false on error
     */
    public function captureGalaxy(array $user, array $galaxy)
    {
        if (empty($galaxy['uuid'])) {
            return false;
        }

        $existingGalaxy = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Galaxy.uuid' => $galaxy['uuid']],
        ]);

        unset($galaxy['id']);
        $galaxy['default'] = false;
        if (!empty($existingGalaxy)) {
            // check if provided galaxy has the same fields as galaxy that are saved in database
            $fieldsToSave = [];
            foreach (array_keys(array_intersect_key($existingGalaxy, $galaxy)) as $key) {
                if ($existingGalaxy['Galaxy'][$key] != $galaxy[$key]) {
                    $fieldsToSave[$key] = $galaxy[$key];
                }
            }
        } else {
            $fieldsToSave = $galaxy;
        }

        if (empty($fieldsToSave) && !empty($existingGalaxy)) {
            return $existingGalaxy; // galaxy already exists and galaxy fields are the same
        }

        if (!$user['Role']['perm_site_admin'] && !$user['Role']['perm_galaxy_editor']) {
            return false; // user has no permission to modify galaxy
        }

        if (empty($existingGalaxy)) {
            $this->create();
        }

        $this->save($fieldsToSave);
        return $this->find('first', [
            'recursive' => -1,
            'conditions' => ['Galaxy.id' => $this->id],
        ]);
    }

    /**
     * Import all clusters into the Galaxy they are shipped with, creating the galaxy if not existant.
     *
     * This function is meant to be used with manual import or push from remote instance
     * @param array $user
     * @param array $clusters clusters to import
     * @return array The import result with errors if any
     */
    public function importGalaxyAndClusters(array $user, array $clusters)
    {
        $results = array('success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 0, 'errors' => array());
        foreach ($clusters as $cluster) {
            if (!empty($cluster['GalaxyCluster']['Galaxy'])) {
                $existingGalaxy = $this->captureGalaxy($user, $cluster['GalaxyCluster']['Galaxy']);
            } elseif (!empty($cluster['GalaxyCluster']['type'])) {
                $existingGalaxy = $this->find('first', array(
                    'recursive' => -1,
                    'fields' => array('id'),
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

    /**
     * Fetches a galaxy and checks if the user has the authorization to perform the requested operation
     *
     * @param  array $user
     * @param  int|string|array $galaxy
     * @param  mixed $authorizations the requested actions to be performed on the galaxy
     * @param  bool  $throwErrors Should the function throws exception if users is not allowed to perform the action
     * @param  bool  $full
     * @return array The galaxy or an error message
     */
    public function fetchIfAuthorized(array $user, $galaxy, $authorizations, $throwErrors=true, $full=false)
    {
        $authorizations = is_array($authorizations) ? $authorizations : [$authorizations];
        $possibleAuthorizations = ['view', 'edit', 'delete'];
        if (!empty(array_diff($authorizations, $possibleAuthorizations))) {
            throw new NotFoundException(__('Invalid authorization requested'));
        }
        if (isset($galaxy['uuid'])) {
            $galaxy[$this->alias] = $galaxy;
        }
        if (!isset($galaxy[$this->alias]['uuid'])) {
            $galaxy = $this->fetchGalaxyById($user, $galaxy, $throwErrors, $full);
            if (empty($galaxy)) {
                $message = __('Invalid galaxy');
                if ($throwErrors) {
                    throw new NotFoundException($message);
                }
                return array('authorized' => false, 'error' => $message);
            }
        }
        if ($user['Role']['perm_site_admin']) {
            return $galaxy;
        }

        if (in_array('view', $authorizations) && count($authorizations) === 1) {
            return $galaxy;
        } else {
            if (!$user['Role']['perm_galaxy_editor']) {
                $message = __('You don\'t have the permission to do that.');
                if ($throwErrors) {
                    throw new MethodNotAllowedException($message);
                }
                return array('authorized' => false, 'error' => $message);
            }
            if (in_array('edit', $authorizations) || in_array('delete', $authorizations)) {
                if ($galaxy[$this->alias]['orgc_id'] != $user['org_id']) {
                    $message = __('Only the creator organisation can modify the galaxy');
                    if ($throwErrors) {
                        throw new MethodNotAllowedException($message);
                    }
                    return array('authorized' => false, 'error' => $message);
                }
            }
            if (in_array('publish', $authorizations)) {
                if ($galaxy[$this->alias]['orgc_id'] != $user['org_id'] && $user['Role']['perm_publish']) {
                    $message = __('Only the creator organisation with publishing capabilities can publish the galaxy');
                    if ($throwErrors) {
                        throw new MethodNotAllowedException($message);
                    }
                    return array('authorized' => false, 'error' => $message);
                }
            }
            return $galaxy;
        }
    }

    /**
     * Simple ACL-aware method to fetch a galaxy by Id or UUID
     *
     * @param array $user
     * @param int|string $id Galaxy ID or UUID
     * @param bool $throwErrors
     * @param bool $full
     * @return array
     */
    public function fetchGalaxyById(array $user, $id, $throwErrors=true, $full=false)
    {
        $alias = $this->alias;
        if (Validation::uuid($id)) {
            $conditions = array("{$alias}.uuid" => $id);
        } elseif (is_numeric($id)) {
            $conditions = array("{$alias}.id" => $id);
        } else{
            if ($throwErrors) {
                throw new NotFoundException(__('Invalid galaxy'));
            }
            return array();
        }

        return $this->fetchGalaxies($user, ['conditions' => $conditions, 'first' => true], $full=$full);
    }

    /**
     * fetchGalaxies Very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
     *
     * @param  mixed $user
     * @param  mixed $options
     * @param  bool  $full
     * @return array
     */
    public function fetchGalaxies(array $user, array $options, $full=false, $includeFullClusterRelationship=false)
    {
        $params = [
            'conditions' => $this->buildConditions($user),
            'recursive' => -1,
            'contain' => [
                'Orgc',
                'Org',
            ],
        ];
        if (!empty($options['contain'])) {
            $params['contain'] = $options['contain'];
        }
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
        }
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (isset($options['group'])) {
            $params['group'] = $options['group'];
        }
        if (!empty($options['order'])) {
            $params['order'] = $this->findOrder(
                $options['order'],
                'GalaxyCluster',
                ['id', 'version', 'name', 'namesapce', 'distribution', 'orgc_id', 'org_id']
            );
        }
        if (isset($options['page'])) {
            $params['page'] = $options['page'];
        }
        if (isset($options['limit'])) {
            $params['limit'] = $options['limit'];
        }
        if (isset($options['list']) && $options['list']) {
            return $this->find('list', $params);
        }

        if (isset($options['first']) && $options['first']) {
            $galaxies = $this->find('first', $params);
        } else if (isset($options['count']) && $options['count']) {
            return $this->find('count', $params);
        } else if (isset($options['column']) && $options['column']) {
            $galaxies = $this->find('all', $params);
            return Hash::extract($galaxies, '{n}.Galaxy.id');
        } else {
            $galaxies = $this->find('all', $params);
        }

        if (empty($galaxies)) {
            return $galaxies;
        }

        if (isset($options['first']) && $options['first']) {
            $galaxies = [$galaxies];
        }

        if ($full) {
            foreach ($galaxies as $i => $galaxy) {
                $galaxies[$i]['GalaxyCluster'] = $this->GalaxyCluster->fetchGalaxyClusters($user, [
                    'conditions' => [
                        'galaxy_id' => $galaxy['Galaxy']['id'],
                    ],
                ], true);
            }
        }

        foreach ($galaxies as $i => $galaxy) {
            $galaxies[$i] = $this->arrangeData($galaxies[$i]);
        }
        if (isset($options['first']) && $options['first']) {
            return $galaxies[0];
        }

        return $galaxies;
    }

    public function buildConditions($user)
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $alias = $this->alias;
            $conditions['AND']['OR'] = [
                "{$alias}.default" => true,
                "{$alias}.org_id" => $user['org_id'],
                [
                    'AND' => [
                        "{$alias}.distribution >" => 0,
                        "{$alias}.distribution <" => 4
                    ],
                ],
            ];
        }
        return $conditions;
    }


    /**
     * arrangeData Move linked data into the galaxy model key
     *
     * @return array The arranged galaxy
     */
    public function arrangeData($galaxy)
    {
        $models = ['GalaxyCluster', 'Org', 'Orgc',];
        foreach ($models as $model) {
            if (isset($galaxy[$model])) {
                $galaxy['Galaxy'][$model] = $galaxy[$model];
                unset($galaxy[$model]);
            }
        }
        return $galaxy;
    }

    public function editGalaxy($user, $galaxy)
    {
        $errors = [];
        if (!$user['Role']['perm_galaxy_editor'] && !$user['Role']['perm_site_admin']) {
            $errors[] = __('Incorrect permission');
        }
        if (isset($galaxy['Galaxy']['uuid'])) {
            $existingGalaxy = $this->find('first', [
                'conditions' => array('Galaxy.uuid' => $galaxy['Galaxy']['uuid'])
            ]);
        } else {
            $errors[] = __('UUID not provided');
        }
        if (empty($existingGalaxy)) {
            $errors[] = __('Unkown UUID');
        } else {
            if (!empty($existingGalaxy['Galaxy']['default'])) {
                $errors[] = __('Cannot edit default Galaxy');
            }
            if (!($existingGalaxy['Galaxy']['orgc_id'] === $user['org_id'] || $user['Role']['perm_site_admin'])) {
                $errors[] = [
                    __('Galaxy could not be saved: The user used to edit the galaxy is not authorised to do so. This can be caused by the user not being of the same organisation as the original creator of the galaxy whilst also not being a site administrator.')
                ];
            }
            $galaxy['Galaxy']['id'] = $existingGalaxy['Galaxy']['id'];

            if (empty($errors)) {
                $date = new DateTime();
                $galaxy['Galaxy']['version'] = $date->getTimestamp();
                if (empty($fieldList)) {
                    $fieldList = ['name', 'namespace', 'description', 'version', 'distribution', 'icon', 'enabled', 'kill_chain_order'];
                }
                $saveSuccess = $this->save($galaxy, ['fieldList' => $fieldList]);
                if (!$saveSuccess) {
                    foreach ($this->validationErrors as $validationError) {
                        $errors[] = $validationError[0];
                    }
                }
            }
        }
        return $errors;
    }

    /**
     * @param array $user
     * @param string $targetType
     * @param int $targetId
     * @return array
     */
    public function fetchTarget(array $user, $targetType, $targetId)
    {
        $this->Tag = ClassRegistry::init('Tag');
        if ($targetType === 'event') {
            return $this->Tag->EventTag->Event->fetchSimpleEvent($user, $targetId);
        } elseif ($targetType === 'attribute') {
            return $this->Tag->AttributeTag->Attribute->fetchAttributeSimple($user, array('conditions' => array('Attribute.id' => $targetId)));
        } elseif ($targetType === 'tag_collection') {
            $target = $this->Tag->TagCollectionTag->TagCollection->fetchTagCollection($user, array('conditions' => array('TagCollection.id' => $targetId)));
            if (!empty($target)) {
                $target = $target[0];
            }
            return $target;
        } else {
            throw new InvalidArgumentException("Invalid target type $targetType");
        }
    }

    /**
     * @param array $user
     * @param string $targetType Can be 'event', 'attribute' or 'tag_collection'
     * @param array $target
     * @param int $cluster_id
     * @param bool $local
     * @return string
     * @throws Exception
     */
    public function attachCluster(array $user, $targetType, array $target, $cluster_id, $local = false)
    {
        $connectorModel = Inflector::camelize($targetType) . 'Tag';
        $local = $local == 1 || $local === true ? 1 : 0;
        $cluster_alias = $this->GalaxyCluster->alias;
        $galaxy_alias = $this->alias;
        $cluster = $this->GalaxyCluster->fetchGalaxyClusters($user, array(
            'first' => true,
            'conditions' => array("${cluster_alias}.id" => $cluster_id),
            'contain' => array('Galaxy'),
            'fields' => array('tag_name', 'id', 'value', "${galaxy_alias}.local_only"),
        ));

        if (empty($cluster)) {
            throw new NotFoundException(__('Invalid Galaxy cluster'));
        }
        $local_only = $cluster['GalaxyCluster']['Galaxy']['local_only'];
        if ($local_only && !$local) {
            throw new MethodNotAllowedException(__("This Cluster can only be attached in a local scope"));
        }
        $this->Tag = ClassRegistry::init('Tag');
        $tag_id = $this->Tag->captureTag(array('name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1, 'local_only' => $local_only), $user, true);
        if ($targetType === 'event') {
            $target_id = $target['Event']['id'];
        } elseif ($targetType === 'attribute') {
            $target_id = $target['Attribute']['id'];
        } else {
            $target_id = $target['TagCollection']['id'];
        }
        $existingTag = $this->Tag->$connectorModel->hasAny(array($targetType . '_id' => $target_id, 'tag_id' => $tag_id));
        if ($existingTag) {
            return 'Cluster already attached.';
        }
        $this->Tag->$connectorModel->create();
        $toSave = array($targetType . '_id' => $target_id, 'tag_id' => $tag_id, 'local' => $local);
        if ($targetType === 'attribute') {
            $toSave['event_id'] = $target['Attribute']['event_id'];
        }
        $result = $this->Tag->$connectorModel->save($toSave);
        if ($result) {
            if (!$local) {
                if ($targetType === 'attribute') {
                    $this->Tag->AttributeTag->Attribute->touch($target);
                } elseif ($targetType === 'event') {
                    $this->Tag->EventTag->Event->unpublishEvent($target);
                }
            }
            if ($targetType === 'attribute' || $targetType === 'event') {
                $this->Tag->EventTag->Event->insertLock($user, $target['Event']['id']);
            }
            $logTitle = 'Attached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') to ' . $targetType . ' (' . $target_id . ')';
            $this->loadLog()->createLogEntry($user, 'galaxy', ucfirst($targetType), $target_id, $logTitle);
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
                ($target_type === 'tag_collection' && !$user['Role']['perm_tag_editor']) ||
                ($target_type !== 'tag_collection' && !$user['Role']['perm_tagger']) ||
                ($user['org_id'] !== $org_id && $user['org_id'] !== $orgc_id)
            ) {
                throw new MethodNotAllowedException('Invalid ' . Inflector::humanize($target_type) . '.');
            }
        }

        $tag_id = $this->Tag->captureTag(array('name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1), $user);

        if ($target_type === 'attribute') {
            $existingTargetTag = $this->Tag->AttributeTag->find('first', array(
                'conditions' => array('AttributeTag.tag_id' => $tag_id, 'AttributeTag.attribute_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($target_type === 'event') {
            $existingTargetTag = $this->Tag->EventTag->find('first', array(
                'conditions' => array('EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($target_type === 'tag_collection') {
            $existingTargetTag = $this->Tag->TagCollectionTag->TagCollection->find('first', array(
                'conditions' => array('tag_id' => $tag_id, 'tag_collection_id' => $target_id),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        }

        if (empty($existingTargetTag)) {
            return 'Cluster not attached.';
        }

        if ($target_type === 'event') {
            $result = $this->Tag->EventTag->delete($existingTargetTag['EventTag']['id']);
        } elseif ($target_type === 'attribute') {
            $result = $this->Tag->AttributeTag->delete($existingTargetTag['AttributeTag']['id']);
        } elseif ($target_type === 'tag_collection') {
            $result = $this->Tag->TagCollectionTag->delete($existingTargetTag['TagCollectionTag']['id']);
        }

        if ($result) {
            if ($target_type !== 'tag_collection') {
                $this->Tag->EventTag->Event->insertLock($user, $event['Event']['id']);
                $this->Tag->EventTag->Event->unpublishEvent($event);
            }

            $logTitle = 'Detached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') to ' . $target_type . ' (' . $target_id . ')';
            $this->loadLog()->createLogEntry($user, 'galaxy', ucfirst($target_type), $target_id, $logTitle);
            return 'Cluster detached';
        } else {
            return 'Could not detach cluster';
        }
    }

    /**
     * @param array $user
     * @param int $targetId
     * @param string $targetType Can be 'attribute', 'event' or 'tag_collection'
     * @param int $tagId
     * @return void
     * @throws Exception
     */
    public function detachClusterByTagId(array $user, $targetId, $targetType, $tagId)
    {
        if ($targetType === 'attribute') {
            $attribute = $this->GalaxyCluster->Tag->EventTag->Event->Attribute->find('first', array(
                'recursive' => -1,
                'fields' => array('id', 'event_id'),
                'conditions' => array('Attribute.id' => $targetId)
            ));
            if (empty($attribute)) {
                throw new NotFoundException('Invalid Attribute.');
            }
            $event_id = $attribute['Attribute']['event_id'];
        } elseif ($targetType === 'event') {
            $event_id = $targetId;
        } elseif ($targetType !== 'tag_collection') {
            throw new InvalidArgumentException('Invalid target type');
        }

        if ($targetType === 'tag_collection') {
            $tag_collection = $this->GalaxyCluster->Tag->TagCollectionTag->TagCollection->fetchTagCollection($user, array(
                'conditions' => array('TagCollection.id' => $targetId),
                'recursive' => -1,
            ));
            if (empty($tag_collection)) {
                throw new NotFoundException('Invalid Tag Collection');
            }
            $tag_collection = $tag_collection[0];
            if (!$user['Role']['perm_site_admin']) {
                if (!$user['Role']['perm_tag_editor'] || $user['org_id'] !== $tag_collection['TagCollection']['org_id']) {
                    throw new NotFoundException('Invalid Tag Collection');
                }
            }
        } else {
            $event = $this->GalaxyCluster->Tag->EventTag->Event->fetchSimpleEvent($user, $event_id);
            if (empty($event)) {
                throw new NotFoundException('Invalid Event.');
            }
            if (!$user['Role']['perm_site_admin'] && !$user['Role']['perm_sync']) {
                if (!$user['Role']['perm_tagger'] || ($user['org_id'] !== $event['Event']['org_id'] && $user['org_id'] !== $event['Event']['orgc_id'])) {
                    throw new NotFoundException('Invalid Event.');
                }
            }
        }

        if ($targetType === 'attribute') {
            $existingTargetTag = $this->GalaxyCluster->Tag->AttributeTag->find('first', array(
                'conditions' => array('AttributeTag.tag_id' => $tagId, 'AttributeTag.attribute_id' => $targetId),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($targetType === 'event') {
            $existingTargetTag = $this->GalaxyCluster->Tag->EventTag->find('first', array(
                'conditions' => array('EventTag.tag_id' => $tagId, 'EventTag.event_id' => $targetId),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        } elseif ($targetType === 'tag_collection') {
            $existingTargetTag = $this->GalaxyCluster->Tag->TagCollectionTag->find('first', array(
                'conditions' => array('TagCollectionTag.tag_id' => $tagId, 'TagCollectionTag.tag_collection_id' => $targetId),
                'recursive' => -1,
                'contain' => array('Tag')
            ));
        }

        if (empty($existingTargetTag)) {
            throw new NotFoundException('Galaxy not attached.');
        }

        $cluster = $this->GalaxyCluster->find('first', array(
            'recursive' => -1,
            'conditions' => array('GalaxyCluster.tag_name' => $existingTargetTag['Tag']['name'])
        ));
        if (empty($cluster)) {
            throw new NotFoundException('Tag is not cluster');
        }

        if ($targetType === 'event') {
            $result = $this->GalaxyCluster->Tag->EventTag->delete($existingTargetTag['EventTag']['id']);
        } elseif ($targetType === 'attribute') {
            $result = $this->GalaxyCluster->Tag->AttributeTag->delete($existingTargetTag['AttributeTag']['id']);
        } elseif ($targetType === 'tag_collection') {
            $result = $this->GalaxyCluster->Tag->TagCollectionTag->delete($existingTargetTag['TagCollectionTag']['id']);
        }
        if (!$result) {
            throw new RuntimeException('Could not detach galaxy from event.');
        }

        if ($targetType !== 'tag_collection') {
            $this->GalaxyCluster->Tag->EventTag->Event->unpublishEvent($event);
        }

        $logTitle = 'Detached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') from ' . $targetType . ' (' . $targetId . ')';
        $this->loadLog()->createLogEntry($user, 'galaxy', ucfirst($targetType), $targetId, $logTitle);
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

    public function getAllowedMatrixGalaxies(array $user)
    {
        $conditions = array(
            'NOT' => array(
                'kill_chain_order' => ''
            ),
            $this->buildConditions($user),
        );
        $galaxies = $this->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions,
        ));
        return $galaxies;
    }

    public function getMatrix($user, $galaxy_id, $scores=[])
    {
        $sectionInEnterprise = ['attack-PRE', 'attack-Windows', 'attack-Linux', 'attack-macOS', 'attack-Office-365', 'attack-Azure-AD', 'attack-Google-Workspace', 'attack-SaaS', 'attack-IaaS', 'attack-Network', 'attack-Containers'];
        $conditions = ['Galaxy.id' => $galaxy_id, 'AND' => $this->buildConditions($user)];
        $contains = [
            'GalaxyCluster' => ['GalaxyElement'],
        ];

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

        // FIXME: temporary fix: create a fake tab to have an unfiltered view of mitre-attach-pattern galaxy
        $mitreAttackGalaxyId = $this->getMitreAttackGalaxyId();
        if ($galaxy_id == $mitreAttackGalaxyId) {
            $tabs['attack-enterprise'] = [];
            $killChainEnterpriseColumn = [];
            foreach ($matrixData['killChain'] as $tabname => $columns) {
                if (in_array($tabname, $sectionInEnterprise)) {
                    foreach ($columns as $column) {
                        $killChainEnterpriseColumn[$column] = 1;
                    }
                }
            }
            $matrixData['killChain'] = ['attack-enterprise' => array_keys($killChainEnterpriseColumn)] + $matrixData['killChain'];
        }
        // end FIXME

        foreach ($clusters as $cluster) {
            if (empty($cluster['GalaxyElement'])) {
                continue;
            }

            $toBeAdded = false;
            $clusterType = $cluster['type'];
            $galaxyElements = $cluster['GalaxyElement'];
            $uniqueClusterForColumn = [];
            foreach ($galaxyElements as $element) {
                // add cluster if kill_chain is present
                if ($element['key'] == 'kill_chain') {
                    $kc = explode(":", $element['value']);
                    $galaxyType = $kc[0];
                    $kc = $kc[1];
                    $cols[$galaxyType][$kc][] = $cluster;
                    $toBeAdded = true;

                    // FIXME: temporary fix: create a fake tab to have an unfiltered view of mitre-attach-pattern galaxy
                    $uniqueClusterKey = sprintf('%s_%s', $kc, $cluster['uuid']);
                    if (
                        $galaxy_id == $mitreAttackGalaxyId && in_array($galaxyType, $sectionInEnterprise) &&
                        empty($uniqueClusterForColumn[$uniqueClusterKey])
                    ) {
                        $cols['attack-enterprise'][$kc][] = $cluster;
                        $uniqueClusterForColumn[$uniqueClusterKey] = true;
                    }
                    // end FIXME
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
        $fieldsToSave = ['description', 'uuid', 'value'];
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
