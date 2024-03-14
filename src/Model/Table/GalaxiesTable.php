<?php

namespace App\Model\Table;

use App\Lib\Tools\FileAccessTool;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Core\Configure;
use Cake\Datasource\ConnectionManager;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Utility\Inflector;
use Exception;
use GlobIterator;
use InvalidArgumentException;
use RuntimeException;

/**
 * @property GalaxyClusters $GalaxyCluster
 * @property Galaxy $Galaxy
 */
class GalaxiesTable extends AppTable
{
    public $useTable = 'galaxies';

    public $recursive = -1;

    private $galaxiesPath;
    private $galaxyClustersPath;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior(
            'JsonFields',
            [
                'fields' => [
                    'kill_chain_order' => ['default' => []],
                    'authors' => ['default' => []]
                ],
            ]
        );

        $this->hasMany(
            'GalaxyClusters',
            [
                'dependent' => true,
                'propertyName' => 'GalaxyCluster'
            ]
        );
        $this->setDisplayField('name');

        $this->galaxiesPath = Configure::read('MISP.custom_galaxies_path', APP . '../libraries' . DS . 'misp-galaxy' . DS . 'galaxies' . DS . '*.json');
        $this->galaxyClustersPath = Configure::read('MISP.custom_galaxy_clusters_path', APP . '../libraries' . DS . 'misp-galaxy' . DS . 'clusters' . DS . '*.json');
    }

    public function beforeDelete(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $this->GalaxyClusters->deleteAll(['GalaxyCluster.galaxy_id' => $entity->id]);
    }

    /**
     * @param bool $force
     * @return array Galaxy type => Galaxy ID
     * @throws Exception
     */
    private function __load_galaxies($force = false)
    {
        $files = new GlobIterator($this->galaxiesPath);
        $galaxies = [];
        foreach ($files as $file) {
            $galaxies[] = FileAccessTool::readJsonFromFile($file->getPathname());
        }
        $existingGalaxies = $this->find(
            'all',
            [
                'fields' => ['uuid', 'version', 'id', 'icon'],
                'recursive' => -1
            ]
        )->toArray();
        $existingGalaxies = array_column($existingGalaxies, null, 'uuid');
        foreach ($galaxies as $galaxy) {
            if (isset($existingGalaxies[$galaxy['uuid']])) {
                if (
                    $force ||
                    $existingGalaxies[$galaxy['uuid']]['version'] < $galaxy['version'] ||
                    (!empty($galaxy['icon']) && ($existingGalaxies[$galaxy['uuid']]['icon'] != $galaxy['icon']))
                ) {
                    $galaxy['id'] = $existingGalaxies[$galaxy['uuid']]['id'];
                    $galaxyEntity = $this->newEntity($galaxy);
                    $this->save($galaxyEntity);
                }
            } else {
                $galaxyEntity = $this->newEntity($galaxy);
                $this->save($galaxyEntity);
            }
        }
        return $this->find(
            'list',
            [
                'recursive' => -1,
                'keyField' => 'type',
                'valueField' => 'id'
            ]
        )->toArray();
    }

    private function __update_prepare_template(array $cluster_package, array $galaxies)
    {
        return [
            'source' => isset($cluster_package['source']) ? $cluster_package['source'] : '',
            'authors' => $cluster_package['authors'],
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
        $temp = $this->GalaxyClusters->find(
            'all',
            [
                'conditions' => [
                    'GalaxyClusters.galaxy_id' => $galaxies[$cluster_package['type']]
                ],
                'recursive' => -1,
                'fields' => ['version', 'id', 'value', 'uuid']
            ]
        )->toArray();
        return array_column(array_column($temp, 'GalaxyCluster'), null, 'value');
    }

    private function __deleteOutdated(bool $force, array $cluster_package, array $existingClusters)
    {
        // Delete all existing outdated clusters
        $cluster_ids_to_delete = [];
        $cluster_uuids_to_delete = [];
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
            $this->GalaxyClusters->GalaxyElement->deleteAll(['GalaxyElement.galaxy_cluster_id' => $cluster_ids_to_delete], false);
            $this->GalaxyClusters->GalaxyClusterRelation->deleteAll(['GalaxyClusterRelation.galaxy_cluster_uuid' => $cluster_uuids_to_delete]);
            $this->GalaxyClusters->deleteAll(['GalaxyCluster.id' => $cluster_ids_to_delete], false);
        }
        return $cluster_package;
    }

    private function __createClusters($cluster_package, $template)
    {
        $relations = [];
        $elements = [];

        $conn = ConnectionManager::get('default');

        $GalaxyClustersTable = $this->fetchTable('GalaxyClusters');
        $LogTable = $this->fetchTable('Logs');

        $conn->transactional(
            function ($conn) use ($GalaxyClustersTable, $LogTable, $cluster_package, $template, &$relations, &$elements) {
                foreach ($cluster_package['values'] as $cluster) {
                    if (empty($cluster['version'])) {
                        $cluster['version'] = 1;
                    }
                    $template['version'] = $cluster['version'];

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
                    $clusterEntity = $GalaxyClustersTable->newEntity($cluster_to_save);

                    try {
                        $GalaxyClustersTable->saveOrFail($clusterEntity, ['atomic' => false, 'validate' => false]);
                    } catch (Exception $e) {
                        $this->log("Could not save galaxy cluster with UUID {$cluster_to_save['uuid']}, error: {$e->getMessage()}.");
                        continue;
                    }
                    $galaxyClusterId = $clusterEntity->id;
                    if (isset($cluster['meta'])) {
                        foreach ($cluster['meta'] as $key => $value) {
                            if (!is_array($value)) {
                                $value = [$value];
                            }
                            foreach ($value as $v) {
                                if (is_array($v)) {
                                    $logEntry = $LogTable->newEntity(
                                        [
                                            'org' => 'SYSTEM',
                                            'model' => 'Galaxy',
                                            'model_id' => 0,
                                            'email' => 0,
                                            'action' => 'error',
                                            'title' => sprintf('Found a malformed galaxy cluster (%s) during the update, skipping. Reason: Malformed meta field, embedded array found.', $cluster['uuid']),
                                            'change' => ''
                                        ]
                                    );
                                    $LogTable->save($logEntry);
                                } else {
                                    $elements[] = [
                                        'galaxy_cluster_id' => $galaxyClusterId,
                                        'key' => $key,
                                        'value' => (string)$v
                                    ];
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
            }
        );

        return [$elements, $relations];
    }

    public function update($force = false)
    {
        $galaxies = $this->__load_galaxies($force);
        $files = new GlobIterator($this->galaxyClustersPath);
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
                $GalaxyElementsTable = $this->fetchTable('GalaxyElements');
                $GalaxyElementsTable->saveMany($GalaxyElementsTable->newEntities($elements));
            }
            $allRelations = array_merge($allRelations, $relations);
        }
        // Save relation as last part when all clusters are created
        if (!empty($allRelations)) {
            $GalaxyClusterRelationsTable = $this->fetchTable('GalaxyClusterRelations');
            $GalaxyClusterRelationsTable->bulkSaveRelations($allRelations);
        }
        // Probably unnecessary anymore
        $this->GalaxyClusters->generateMissingRelations();
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
        $existingGalaxy = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['Galaxies.uuid' => $galaxy['uuid']]
            ]
        )->first();
        $existingGalaxy = $existingGalaxy ? $existingGalaxy->toArray() : null;

        if (empty($existingGalaxy)) {
            if ($user['Role']['perm_site_admin'] || $user['Role']['perm_galaxy_editor']) {
                unset($galaxy['id']);
                $galaxyEntity = $this->newEntity($galaxy);
                $this->save($galaxyEntity);
                $existingGalaxy = $this->find(
                    'all',
                    [
                        'recursive' => -1,
                        'conditions' => ['Galaxies.id' => $galaxyEntity->id]
                    ]
                )->first()->toArray();
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
     * @param array $user
     * @param array $clusters clusters to import
     * @return array The import result with errors if any
     */
    public function importGalaxyAndClusters(array $user, array $clusters)
    {
        $results = ['success' => false, 'imported' => 0, 'ignored' => 0, 'failed' => 0, 'errors' => []];
        foreach ($clusters as $cluster) {
            if (!empty($cluster['GalaxyCluster']['Galaxy'])) {
                $existingGalaxy = $this->captureGalaxy($user, $cluster['GalaxyCluster']['Galaxy']);
            } elseif (!empty($cluster['GalaxyCluster']['type'])) {
                $existingGalaxy = $this->find(
                    'all',
                    [
                        'recursive' => -1,
                        'fields' => ['id'],
                        'conditions' => ['Galaxies.type' => $cluster['GalaxyCluster']['type']],
                    ]
                )->first();
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
            $cluster['GalaxyCluster']['galaxy_id'] = $existingGalaxy['id'];
            $cluster['GalaxyCluster']['locked'] = true;
            $saveResult = $this->GalaxyClusters->captureCluster($user, $cluster, $fromPull = false);
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
     * @param array $user
     * @param string $targetType
     * @param int $targetId
     * @return array
     */
    public function fetchTarget(array $user, $targetType, $targetId)
    {
        $TagsTable = $this->fetchTable('Tags');
        if ($targetType === 'event') {
            return $TagsTable->EventTag->Event->fetchSimpleEvent($user, $targetId);
        } elseif ($targetType === 'attribute') {
            return $TagsTable->AttributeTag->Attribute->fetchAttributeSimple($user, ['conditions' => ['Attribute.id' => $targetId]]);
        } elseif ($targetType === 'tag_collection') {
            $target = $TagsTable->TagCollectionTag->TagCollection->fetchTagCollection($user, ['conditions' => ['TagCollection.id' => $targetId]]);
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
        $cluster_alias = $this->GalaxyClusters->alias;
        $galaxy_alias = $this->getAlias();
        $cluster = $this->GalaxyClusters->fetchGalaxyClusters(
            $user,
            [
                'all' => true,
                'conditions' => ["$cluster_alias.id" => $cluster_id],
                'contain' => ['Galaxy'],
                'fields' => ['tag_name', 'id', 'value', "$galaxy_alias.local_only"],
            ]
        )->first();

        if (empty($cluster)) {
            throw new NotFoundException(__('Invalid Galaxy cluster'));
        }
        $local_only = $cluster['GalaxyCluster']['Galaxy']['local_only'];
        if ($local_only && !$local) {
            throw new MethodNotAllowedException(__("This Cluster can only be attached in a local scope"));
        }
        $TagsTable = $this->fetchTable('Tags');
        $tag_id = $TagsTable->captureTag(['name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1, 'local_only' => $local_only], $user, true);
        if ($targetType === 'event') {
            $target_id = $target['Event']['id'];
        } elseif ($targetType === 'attribute') {
            $target_id = $target['Attribute']['id'];
        } else {
            $target_id = $target['TagCollection']['id'];
        }
        $existingTag = $TagsTable->$connectorModel->hasAny([$targetType . '_id' => $target_id, 'tag_id' => $tag_id]);
        if ($existingTag) {
            return 'Cluster already attached.';
        }
        $TagsTable->$connectorModel->create();
        $toSave = [$targetType . '_id' => $target_id, 'tag_id' => $tag_id, 'local' => $local];
        if ($targetType === 'attribute') {
            $toSave['event_id'] = $target['Attribute']['event_id'];
        }
        $result = $TagsTable->$connectorModel->save($toSave);
        if ($result) {
            if (!$local) {
                if ($targetType === 'attribute') {
                    $TagsTable->AttributeTag->Attribute->touch($target);
                } elseif ($targetType === 'event') {
                    $TagsTable->EventTag->Event->unpublishEvent($target);
                }
            }
            if ($targetType === 'attribute' || $targetType === 'event') {
                $TagsTable->EventTag->Event->insertLock($user, $target['Event']['id']);
            }
            $logTitle = 'Attached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') to ' . $targetType . ' (' . $target_id . ')';
            $this->loadLog()->createLogEntry($user, 'galaxy', ucfirst($targetType), $target_id, $logTitle);
            return 'Cluster attached.';
        }
        return 'Could not attach the cluster';
    }

    public function detachCluster($user, $target_type, $target_id, $cluster_id)
    {
        $cluster = $this->GalaxyClusters->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['id' => $cluster_id],
                'fields' => ['tag_name', 'id', 'value']
            ]
        )->first();
        $TagsTable = $this->fetchTable('Tags');
        if ($target_type === 'event') {
            $target = $TagsTable->EventTag->Event->fetchEvent($user, ['eventid' => $target_id, 'metadata' => 1]);
            if (empty($target)) {
                throw new NotFoundException(__('Invalid %s.', $target_type));
            }
            $target = $target[0];
            $event = $target;
            $org_id = $event['Event']['org_id'];
            $orgc_id = $event['Event']['orgc_id'];
        } elseif ($target_type === 'attribute') {
            $target = $TagsTable->AttributeTag->Attribute->fetchAttributes($user, ['conditions' => ['Attribute.id' => $target_id], 'flatten' => 1]);
            if (empty($target)) {
                throw new NotFoundException(__('Invalid %s.', $target_type));
            }
            $target = $target[0];
            $event_id = $target['Attribute']['event_id'];
            $event = $TagsTable->EventTag->Event->fetchEvent($user, ['eventid' => $event_id, 'metadata' => 1]);
            if (empty($event)) {
                throw new NotFoundException(__('Invalid event'));
            }
            $event = $event[0];
            $org_id = $event['Event']['org_id'];
            $orgc_id = $event['Event']['org_id'];
        } elseif ($target_type === 'tag_collection') {
            $target = $TagsTable->TagCollectionTag->TagCollection->fetchTagCollection($user, ['conditions' => ['TagCollection.id' => $target_id]]);
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

        $tag_id = $TagsTable->captureTag(['name' => $cluster['GalaxyCluster']['tag_name'], 'colour' => '#0088cc', 'exportable' => 1], $user);

        if ($target_type === 'attribute') {
            $existingTargetTag = $TagsTable->AttributeTag->find(
                'all',
                [
                    'conditions' => ['AttributeTag.tag_id' => $tag_id, 'AttributeTag.attribute_id' => $target_id],
                    'recursive' => -1,
                    'contain' => ['Tag']
                ]
            )->first();
        } elseif ($target_type === 'event') {
            $existingTargetTag = $TagsTable->EventTag->find(
                'all',
                [
                    'conditions' => ['EventTag.tag_id' => $tag_id, 'EventTag.event_id' => $target_id],
                    'recursive' => -1,
                    'contain' => ['Tag']
                ]
            )->first();
        } elseif ($target_type === 'tag_collection') {
            $existingTargetTag = $TagsTable->TagCollectionTag->TagCollection->find(
                'all',
                [
                    'conditions' => ['tag_id' => $tag_id, 'tag_collection_id' => $target_id],
                    'recursive' => -1,
                    'contain' => ['Tag']
                ]
            )->first();
        }

        if (empty($existingTargetTag)) {
            return 'Cluster not attached.';
        }

        if ($target_type === 'event') {
            $result = $TagsTable->EventTag->delete($existingTargetTag['EventTag']['id']);
        } elseif ($target_type === 'attribute') {
            $result = $TagsTable->AttributeTag->delete($existingTargetTag['AttributeTag']['id']);
        } elseif ($target_type === 'tag_collection') {
            $result = $TagsTable->TagCollectionTag->delete($existingTargetTag['TagCollectionTag']['id']);
        }

        if ($result) {
            if ($target_type !== 'tag_collection') {
                $TagsTable->EventTag->Event->insertLock($user, $event['Event']['id']);
                $TagsTable->EventTag->Event->unpublishEvent($event);
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
            $attribute = $this->GalaxyClusters->Tag->EventTag->Event->Attributes->find(
                'all',
                [
                    'recursive' => -1,
                    'fields' => ['id', 'event_id'],
                    'conditions' => ['Attribute.id' => $targetId]
                ]
            )->first();
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
            $tag_collection = $this->GalaxyClusters->Tag->TagCollectionTag->TagCollection->fetchTagCollection(
                $user,
                [
                    'conditions' => ['TagCollection.id' => $targetId],
                    'recursive' => -1,
                ]
            );
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
            $event = $this->GalaxyClusters->Tag->EventTag->Event->fetchSimpleEvent($user, $event_id);
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
            $existingTargetTag = $this->GalaxyClusters->Tag->AttributeTag->find(
                'all',
                [
                    'conditions' => ['AttributeTag.tag_id' => $tagId, 'AttributeTag.attribute_id' => $targetId],
                    'recursive' => -1,
                    'contain' => ['Tag']
                ]
            )->first();
        } elseif ($targetType === 'event') {
            $existingTargetTag = $this->GalaxyClusters->Tag->EventTag->find(
                'all',
                [
                    'conditions' => ['EventTag.tag_id' => $tagId, 'EventTag.event_id' => $targetId],
                    'recursive' => -1,
                    'contain' => ['Tag']
                ]
            )->first();
        } elseif ($targetType === 'tag_collection') {
            $existingTargetTag = $this->GalaxyClusters->Tag->TagCollectionTag->find(
                'all',
                [
                    'conditions' => ['TagCollectionTag.tag_id' => $tagId, 'TagCollectionTag.tag_collection_id' => $targetId],
                    'recursive' => -1,
                    'contain' => ['Tag']
                ]
            )->first();
        }

        if (empty($existingTargetTag)) {
            throw new NotFoundException('Galaxy not attached.');
        }

        $cluster = $this->GalaxyClusters->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['GalaxyCluster.tag_name' => $existingTargetTag['Tag']['name']]
            ]
        )->first();
        if (empty($cluster)) {
            throw new NotFoundException('Tag is not cluster');
        }

        if ($targetType === 'event') {
            $result = $this->GalaxyClusters->Tag->EventTag->delete($existingTargetTag['EventTag']['id']);
        } elseif ($targetType === 'attribute') {
            $result = $this->GalaxyClusters->Tag->AttributeTag->delete($existingTargetTag['AttributeTag']['id']);
        } elseif ($targetType === 'tag_collection') {
            $result = $this->GalaxyClusters->Tag->TagCollectionTag->delete($existingTargetTag['TagCollectionTag']['id']);
        }
        if (!$result) {
            throw new RuntimeException('Could not detach galaxy from event.');
        }

        if ($targetType !== 'tag_collection') {
            $this->GalaxyClusters->Tag->EventTag->Event->unpublishEvent($event);
        }

        $logTitle = 'Detached ' . $cluster['GalaxyCluster']['value'] . ' (' . $cluster['GalaxyCluster']['id'] . ') from ' . $targetType . ' (' . $targetId . ')';
        $this->loadLog()->createLogEntry($user, 'galaxy', ucfirst($targetType), $targetId, $logTitle);
    }

    public function getMitreAttackGalaxyId($type = "mitre-attack-pattern", $namespace = "mitre-attack")
    {
        $galaxy = $this->find(
            'all',
            [
                'recursive' => -1,
                'fields' => ['MAX(Galaxy.version) as latest_version', 'id'],
                'conditions' => [
                    'Galaxies.type' => $type,
                    'Galaxies.namespace' => $namespace
                ],
                'group' => ['name', 'id']
            ]
        )->first();
        return empty($galaxy) ? 0 : $galaxy['Galaxy']['id'];
    }

    public function getAllowedMatrixGalaxies()
    {
        $conditions = [
            'NOT' => [
                'kill_chain_order' => ''
            ]
        ];
        $galaxies = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => $conditions,
            ]
        );
        return $galaxies;
    }

    public function getMatrix($galaxy_id, $scores = [])
    {
        $conditions = ['Galaxies.id' => $galaxy_id];
        $contains = [
            'GalaxyCluster' => ['GalaxyElement'],
        ];

        $galaxy = $this->find(
            'all',
            [
                'recursive' => -1,
                'contain' => $contains,
                'conditions' => $conditions,
            ]
        )->first();

        $mispUUID = Configure::read('MISP')['uuid'];

        if (!isset($galaxy['Galaxy']['kill_chain_order'])) {
            throw new MethodNotAllowedException(__("Galaxy cannot be represented as a matrix"));
        }
        $matrixData = [
            'killChain' => $galaxy['Galaxy']['kill_chain_order'],
            'tabs' => [],
            'matrixTags' => [],
            'instance-uuid' => $mispUUID,
            'galaxy' => $galaxy['Galaxy']
        ];

        $clusters = $galaxy['GalaxyCluster'];
        $cols = [];

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
            $names = ['Enterprise Attack - Attack Pattern', 'Pre Attack - Attack Pattern', 'Mobile Attack - Attack Pattern'];
            $tag_names = [];
            $gals = $this->find(
                'all',
                [
                    'recursive' => -1,
                    'contain' => ['GalaxyCluster.tag_name'],
                    'conditions' => ['Galaxies.name' => $names]
                ]
            );
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
                usort(
                    $tabs[$i][$j],
                    function ($a, $b) use ($scores) {
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
                    }
                );
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
    public function generateForkTree(array $clusters, array $galaxy, $pruneRootLeaves = true)
    {
        $tree = [];
        $lookup = [];
        $lastNodeAdded = [];
        // generate the lookup table used to immediatly get the correct cluster
        foreach ($clusters as $i => $cluster) {
            $clusters[$i]['children'] = [];
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
                    $lastVersionNode = [
                        'isVersion' => true,
                        'isLast' => true,
                        'version' => $parentVersion,
                        'parentUuid' => $parent['GalaxyCluster']['uuid'],
                        'children' => []
                    ];
                    $versionNode = [
                        'isVersion' => true,
                        'isLast' => false,
                        'version' => $clusterVersion,
                        'parentUuid' => $parent['GalaxyCluster']['uuid'],
                        'children' => [&$clusters[$i]]
                    ];
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

        $tree = [
            [
                'Galaxy' => $galaxy['Galaxy'],
                'children' => array_values($tree)
            ]
        ];
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
        $converted['name'] = $galaxy['name'];
        $converted['type'] = $galaxy['type'];
        $converted['authors'] = [];
        $converted['version'] = 0;
        $values = [];
        $fieldsToSave = ['description', 'uuid', 'value', 'extends_uuid', 'extends_version'];
        foreach ($clusters as $i => $cluster) {
            foreach ($fieldsToSave as $field) {
                $values[$i][$field] = $cluster[$field];
            }
            $converted['uuid'] = $cluster['collection_uuid'];
            $converted['source'] = $cluster['source'];
            if (!empty($cluster['authors'])) {
                foreach ($cluster['authors'] as $author) {
                    if (!is_null($author) && $author != 'null') {
                        $converted['authors'][$author] = $author;
                    }
                }
            }
            $converted['version'] = $converted['version'] > $cluster['version'];
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
                        $values[$i]['related'][$j]['tags'][] = $tag['Tag']['name'];
                    }
                }
            }
        }
        $converted['authors'] = array_values($converted['authors']);
        $converted['values'] = $values;
        return $converted;
    }
}
