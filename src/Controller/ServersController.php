<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Lib\Tools\AttachmentTool;
use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\CustomPaginationTool;
use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\HttpTool;
use App\Lib\Tools\JsonTool;
use App\Lib\Tools\RedisTool;
use App\Lib\Tools\SecurityAudit;
use App\Model\Entity\Job;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Http\Exception\ForbiddenException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Cake\Routing\Router;
use Cake\Validation\Validation;
use Exception;
use InvalidArgumentException;
use RuntimeException;
use SplFileInfo;

class ServersController extends AppController
{
    public $paginate = [
        'limit' => 60,
        'recursive' => -1,
        'contain' => [
            'User' => [
                'fields' => ['User.id', 'User.org_id', 'User.email'],
            ],
            'Organisation' => [
                'fields' => ['Organisation.name', 'Organisation.id'],
            ],
            'RemoteOrg' => [
                'fields' => ['RemoteOrg.name', 'RemoteOrg.id'],
            ],
        ],
        'maxLimit' => 9999,
        'order' => [
            'Server.priority' => 'ASC'
        ],
    ];

    public function initialize(): void
    {
        $this->loadComponent('CompressedRequestHandler');
        parent::initialize();
    }

    public function beforeFilter(EventInterface $event)
    {
        $this->Authentication->allowUnauthenticated(['cspReport']); // cspReport must work without authentication

        parent::beforeFilter($event);
        $this->Security->setConfig('unlockedActions', ['cspReport']);
        // permit reuse of CSRF tokens on some pages.
        switch ($this->request->getParam('action')) {
            case 'push':
            case 'pull':
            case 'getVersion':
            case 'testConnection':
                $this->Security->csrfUseOnce = false;
        }
    }

    public function index()
    {
        // Do not fetch server authkey from DB
        $fields = array_flip($this->Servers->getSchema()->columns());
        unset($fields['authkey']);
        $fields = array_keys($fields);

        $filters = $this->harvestParameters(['search']);
        $conditions = [];
        if (!empty($filters['search'])) {
            $strSearch = '%' . trim(strtolower($filters['search'])) . '%';
            $conditions['OR'][]['LOWER(Server.name) LIKE'] = $strSearch;
            $conditions['OR'][]['LOWER(Server.url) LIKE'] = $strSearch;
        }

        if ($this->ParamHandler->isRest()) {
            $params = [
                'fields' => $fields,
                'recursive' => -1,
                'contain' => [
                    'Users' => [
                        'fields' => ['id', 'org_id', 'email', 'server_id'],
                    ],
                    'Organisations' => [
                        'fields' => ['id', 'name', 'uuid', 'nationality', 'sector', 'type'],
                    ],
                    'RemoteOrg' => [
                        'fields' => ['RemoteOrg.id', 'RemoteOrg.name', 'RemoteOrg.uuid', 'RemoteOrg.nationality', 'RemoteOrg.sector', 'RemoteOrg.type'],
                    ],
                ],
                'conditions' => $conditions,
            ];
            $servers = $this->Servers->find('all', $params);
            $servers = $this->Servers->attachServerCacheTimestamps($servers->toArray());
            return $this->RestResponse->viewData($servers, $this->response->getType());
        } else {
            $this->paginate['fields'] = $fields;
            $this->paginate['conditions'] = $conditions;
            $servers = $this->paginate();
            $servers = $this->Servers->attachServerCacheTimestamps($servers);
            $this->set('servers', $servers);
            $collection = [];
            $collection['orgs'] = $this->Servers->Organisation->find(
                'list',
                [
                    'fields' => ['id', 'name'],
                ]
            );
            $TagsTable = $this->fetchTable('Tags');
            $collection['tags'] = $TagsTable->find(
                'list',
                [
                    'fields' => ['id', 'name'],
                ]
            );
            $this->set('collection', $collection);
        }
    }

    public function previewIndex($id)
    {
        $urlparams = '';
        $passedArgs = [];

        $server = $this->Servers->get($id);
        if (empty($server)) {
            throw new NotFoundException('Invalid server ID.');
        }
        $validFilters = $this->Servers->validEventIndexFilters;
        foreach ($validFilters as $k => $filter) {
            if (isset($this->passedArgs[$filter])) {
                $passedArgs[$filter] = $this->passedArgs[$filter];
                if ($k != 0) {
                    $urlparams .= '/';
                }
                $urlparams .= $filter . ':' . $this->passedArgs[$filter];
            }
        }
        $combinedArgs = array_merge($this->passedArgs, $passedArgs);
        if (!isset($combinedArgs['sort'])) {
            $combinedArgs['sort'] = 'timestamp';
            $combinedArgs['direction'] = 'desc';
        }
        if (empty($combinedArgs['page'])) {
            $combinedArgs['page'] = 1;
        }
        if (empty($combinedArgs['limit'])) {
            $combinedArgs['limit'] = 60;
        }
        try {
            list($events, $total_count) = $this->Servers->previewIndex($server, $this->ACL->getUser(), $combinedArgs);
        } catch (Exception $e) {
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->throwException(500, $e->getMessage());
            } else {
                $this->Flash->error(__('Download failed.') . ' ' . $e->getMessage());
                $this->redirect(['action' => 'index']);
            }
        }

        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($events, $this->response->getType());
        }

        $EventsTable = $this->fetchTable('Events');
        $this->set('threatLevels', $EventsTable->ThreatLevel->listThreatLevels());
        $customPagination = new CustomPaginationTool();
        $params = $customPagination->createPaginationRules($events, $this->passedArgs, $this->alias);
        if (!empty($total_count)) {
            $params['pageCount'] = ceil($total_count / $params['limit']);
        }
        $this->params->params['paging'] = ['Servers' => $params];
        if (count($events) > 60) {
            $customPagination->truncateByPagination($events, $params);
        }
        $this->set('events', $events);
        $this->set('eventDescriptions', $EventsTable->fieldDescriptions);
        $this->set('analysisLevels', $EventsTable->analysisLevels);
        $this->set('distributionLevels', $EventsTable->distributionLevels);

        $shortDist = [0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group'];
        $this->set('shortDist', $shortDist);
        $this->set('id', $id);
        $this->set('urlparams', $urlparams);
        $this->set('passedArgs', json_encode($passedArgs));
        $this->set('passedArgsArray', $passedArgs);
        $this->set('server', $server);
    }

    public function previewEvent($serverId, $eventId, $all = false)
    {
        $server = $this->Servers->get($serverId);
        if (empty($server)) {
            throw new NotFoundException('Invalid server ID.');
        }
        try {
            $event = $this->Servers->previewEvent($server, $eventId);
        } catch (NotFoundException $e) {
            throw new NotFoundException(__("Event '%s' not found.", $eventId));
        } catch (Exception $e) {
            $this->Flash->error(__('Download failed. %s', $e->getMessage()));
            $this->redirect(['action' => 'previewIndex', $serverId]);
        }

        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($event, $this->response->getType());
        }

        $WarninglistsTable = $this->fetchTable('Warninglists');
        if (isset($event['Event']['Attribute'])) {
            $WarninglistsTable->attachWarninglistToAttributes($event['Event']['Attribute']);
        }
        if (isset($event['Event']['ShadowAttribute'])) {
            $WarninglistsTable->attachWarninglistToAttributes($event['Event']['ShadowAttribute']);
        }

        $EventsTable = $this->fetchTable('Events');
        $params = $EventsTable->rearrangeEventForView($event, $this->passedArgs, $all);
        $this->__removeGalaxyClusterTags($event);
        $this->params->params['paging'] = ['Server' => $params];
        $this->set('event', $event);
        $this->set('server', $server);
        $dataForView = [
            'Attribute' => ['attrDescriptions' => 'fieldDescriptions', 'distributionDescriptions' => 'distributionDescriptions', 'distributionLevels' => 'distributionLevels'],
            'Event' => ['eventDescriptions' => 'fieldDescriptions', 'analysisLevels' => 'analysisLevels'],
            'Object' => []
        ];
        foreach ($dataForView as $m => $variables) {
            if ($m === 'Event') {
                $currentModel = $EventsTable;
            } elseif ($m === 'Attribute') {
                $currentModel = $EventsTable->Attribute;
            } elseif ($m === 'Object') {
                $currentModel = $EventsTable->Object;
            }
            foreach ($variables as $alias => $variable) {
                $this->set($alias, $currentModel->{$variable});
            }
        }
        $this->set('threatLevels', $EventsTable->ThreatLevel->listThreatLevels());
        $this->set('title_for_layout', __('Remote event preview'));
    }

    private function __removeGalaxyClusterTags(array &$event)
    {
        $galaxyTagIds = [];
        foreach ($event['Galaxy'] as $galaxy) {
            foreach ($galaxy['GalaxyCluster'] as $galaxyCluster) {
                $galaxyTagIds[$galaxyCluster['tag_id']] = true;
            }
        }

        if (empty($galaxyTagIds)) {
            return;
        }

        foreach ($event['Tag'] as $k => $eventTag) {
            if (isset($galaxyTagIds[$eventTag['id']])) {
                unset($event['Tag'][$k]);
            }
        }
    }

    public function compareServers()
    {
        list($servers, $overlap) = $this->Servers->serverEventsOverlap();
        $this->set('servers', $servers);
        $this->set('overlap', $overlap);
        $this->set('title_for_layout', __('Server overlap analysis matrix'));
    }

    public function filterEventIndex($id)
    {
        if (!$this->isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        $validFilters = $this->Servers->validEventIndexFilters;
        $validatedFilterString = '';
        foreach ($this->passedArgs as $k => $v) {
            if (in_array('' . $k, $validFilters)) {
                if ($validatedFilterString != '') {
                    $validatedFilterString .= '/';
                }
                $validatedFilterString .= $k . ':' . $v;
            }
        }
        $this->set('id', $id);
        $this->set('validFilters', $validFilters);
        $this->set('filter', $validatedFilterString);
    }

    public function add()
    {
        if ($this->request->is('post')) {
            $data = $this->request->getData();
            if ($this->ParamHandler->isRest()) {
                if (!isset($data['Server'])) {
                    $data = ['Server' => $data];
                }
            }
            if (!empty($data['Server']['json'])) {
                $json = json_decode($data['Server']['json'], true);
            } elseif ($this->ParamHandler->isRest()) {
                if (empty($data['Server']['remote_org_id'])) {
                    throw new MethodNotAllowedException('No remote org ID set. Please pass it as remote_org_id');
                }
            }
            $fail = false;
            if (empty(Configure::read('MISP.host_org_id'))) {
                $data['Server']['internal'] = 0;
            }

            if (!$fail) {
                if ($this->ParamHandler->isRest()) {
                    $defaults = [
                        'push' => 0,
                        'pull' => 0,
                        'push_sightings' => 0,
                        'push_galaxy_clusters' => 0,
                        'pull_galaxy_clusters' => 0,
                        'caching_enabled' => 0,
                        'json' => '[]',
                        'self_signed' => 0,
                        'remove_missing_tags' => 0
                    ];
                    foreach ($defaults as $default => $dvalue) {
                        if (!isset($data['Server'][$default])) {
                            $data['Server'][$default] = $dvalue;
                        }
                    }
                }
                // force check userid and orgname to be from yourself
                $data['Server']['org_id'] = $this->ACL->getUser()->org_id;
                if ($this->ParamHandler->isRest()) {
                    if (empty($data['Server']['remote_org_id'])) {
                        return $this->RestResponse->saveFailResponse('Servers', 'add', false, ['Organisation' => 'Remote Organisation\'s id/uuid not given (remote_org_id)'], $this->response->getType());
                    }
                    if (Validation::uuid($data['Server']['remote_org_id'])) {
                        $orgCondition = ['uuid' => $data['Server']['remote_org_id']];
                    } else {
                        $orgCondition = ['id' => $data['Server']['remote_org_id']];
                    }
                    $existingOrgs = $this->Servers->Organisations->find(
                        'all',
                        [
                            'conditions' => $orgCondition,
                            'recursive' => -1,
                            'fields' => ['id', 'uuid']
                        ]
                    )->first();
                    if (empty($existingOrgs)) {
                        return $this->RestResponse->saveFailResponse('Servers', 'add', false, ['Organisation' => 'Invalid Remote Organisation'], $this->response->getType());
                    }
                } else {
                    if ($data['Server']['organisation_type'] < 2) {
                        $data['Server']['remote_org_id'] = $json['id'];
                    } else {
                        $existingOrgs = $this->Servers->Organisation->find(
                            'all',
                            [
                                'conditions' => ['uuid' => $json['uuid']],
                                'recursive' => -1,
                                'fields' => ['id', 'uuid']
                            ]
                        )->first();
                        if (!empty($existingOrgs)) {
                            $fail = true;
                            $this->Flash->error(__('That organisation could not be created as the uuid is in use already.'));
                        }
                        if (!$fail) {
                            $this->Servers->Organisation->create();
                            $orgSave = $this->Servers->Organisation->save(
                                [
                                    'name' => $json['name'],
                                    'uuid' => $json['uuid'],
                                    'local' => 0,
                                    'created_by' => $this->ACL->getUser()->id
                                ]
                            );

                            if (!$orgSave) {
                                $this->Flash->error(__('Couldn\'t save the new organisation, are you sure that the uuid is in the correct format? Also, make sure the organisation\'s name doesn\'t clash with an existing one.'));
                                $fail = true;
                                $data['Server']['external_name'] = $json['name'];
                                $data['Server']['external_uuid'] = $json['uuid'];
                            } else {
                                $data['Server']['remote_org_id'] = $this->Servers->Organisation->id;
                                $data['Server']['organisation_type'] = 1;
                            }
                        }
                    }
                }
                if (!$fail) {
                    if (Configure::read('MISP.host_org_id') == 0 || $data['Server']['remote_org_id'] != Configure::read('MISP.host_org_id')) {
                        $data['Server']['internal'] = 0;
                    }
                    $data['Server']['org_id'] = $this->ACL->getUser()->org_id;

                    $serverEntity = $this->Servers->newEntity($data['Server']);

                    try {
                        $this->Servers->saveOrFail($serverEntity);
                        if (isset($data['Server']['submitted_cert'])) {
                            $this->__saveCert($data, $this->Servers->id, false);
                        }
                        if (isset($data['Server']['submitted_client_cert'])) {
                            $this->__saveCert($data, $this->Servers->id, true);
                        }
                        if ($this->ParamHandler->isRest()) {
                            return $this->RestResponse->viewData($serverEntity->toArray(), $this->response->getType());
                        } else {
                            $this->Flash->success(__('The server has been saved'));
                            $this->redirect(['action' => 'index']);
                        }
                    } catch (Exception $e) {
                        if ($this->ParamHandler->isRest()) {
                            return $this->RestResponse->saveFailResponse('Servers', 'add', false, $serverEntity->getErrors(), $this->response->getType());
                        } else {
                            $this->Flash->error(__('The server could not be saved. Please, try again.'));
                        }
                    }
                }
            }
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->describe('Servers', 'add', false, $this->response->getType());
        } else {
            $organisationOptions = [0 => 'Local organisation', 1 => 'External organisation', 2 => 'New external organisation'];

            $temp = $this->Servers->Organisation->find(
                'all',
                [
                    'fields' => ['id', 'name', 'local'],
                    'order' => ['lower(Organisation.name) ASC']
                ]
            );
            $allOrgs = [];
            $localOrganisations = [];
            $externalOrganisations = [];
            foreach ($temp as $o) {
                if ($o['Organisation']['local']) {
                    $localOrganisations[$o['Organisation']['id']] = $o['Organisation']['name'];
                } else {
                    $externalOrganisations[$o['Organisation']['id']] = $o['Organisation']['name'];
                }
                $allOrgs[] = ['id' => $o['Organisation']['id'], 'name' => $o['Organisation']['name']];
            }

            $allTypes = $this->Servers->getAllTypes();

            $this->set('host_org_id', Configure::read('MISP.host_org_id'));
            $this->set('organisationOptions', $organisationOptions);
            $this->set('localOrganisations', $localOrganisations);
            $this->set('externalOrganisations', $externalOrganisations);
            $this->set('allOrganisations', $allOrgs);
            $this->set('allAttributeTypes', $allTypes['attribute']);
            $this->set('allObjectTypes', $allTypes['object']);

            $this->set('allTags', $this->__getTags());
            $this->set('host_org_id', Configure::read('MISP.host_org_id'));
            $this->set('pull_scope', 'server');
            $this->render('edit');
        }
    }

    public function edit($id = null)
    {
        $server = $this->Servers->get($id);
        if (!$server) {
            throw new NotFoundException(__('Invalid server'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $data = $this->request->getData();
            if ($this->ParamHandler->isRest()) {
                if (!isset($data['Server'])) {
                    $data = ['Server' => $data];
                }
            }
            if (empty(Configure::read('MISP.host_org_id'))) {
                $server['internal'] = 0;
            }
            if (isset($data['Server']['json'])) {
                $json = json_decode($data['Server']['json'], true);
            } else {
                $json = null;
            }
            $fail = false;

            if (!empty($data['Server']['push_rules'])) {
                if (!empty($data['Server']['push_rules']['tags'])) {
                    $TagsTable = $this->fetchTable('Tags');
                    foreach ($data['Server']['push_rules']['tags'] as $operator => $list) {
                        foreach ($list as $i => $tagName) {
                            if (!is_numeric($tagName)) { // tag added from freetext
                                $tag_id = $TagsTable->captureTag(['name' => $tagName], $this->ACL->getUser());
                                $list[$i] = $tag_id;
                            }
                        }
                    }
                }
            }

            if (!$fail) {
                // say what fields are to be updated
                $fieldList = ['id', 'url', 'push', 'pull', 'push_sightings', 'push_galaxy_clusters', 'pull_galaxy_clusters', 'caching_enabled', 'unpublish_event', 'publish_without_email', 'remote_org_id', 'name', 'self_signed', 'remove_missing_tags', 'cert_file', 'client_cert_file', 'push_rules', 'pull_rules', 'internal', 'skip_proxy'];
                $server['id'] = $id;
                if (isset($data['Server']['authkey']) && "" != $data['Server']['authkey']) {
                    $fieldList[] = 'authkey';
                }
                if (isset($data['Server']['organisation_type']) && isset($json)) {
                    // adds 'remote_org_id' in the fields to update
                    $fieldList[] = 'remote_org_id';
                    if ($server['organisation_type'] < 2) {
                        $server['remote_org_id'] = $json['id'];
                    } else {
                        $existingOrgs = $this->Servers->Organisation->find(
                            'all',
                            [
                                'conditions' => ['uuid' => $json['uuid']],
                                'recursive' => -1,
                                'fields' => ['id', 'uuid']
                            ]
                        )->first();
                        if (!empty($existingOrgs)) {
                            $fail = true;
                            if ($this->ParamHandler->isRest()) {
                                return $this->RestResponse->saveFailResponse('Servers', 'edit', false, ['Organisation' => 'Remote Organisation\'s uuid already used'], $this->response->getType());
                            } else {
                                $this->Flash->error(__('That organisation could not be created as the uuid is in use already.'));
                            }
                        }

                        if (!$fail) {
                            $this->Servers->Organisation->create();
                            $orgSave = $this->Servers->Organisation->save(
                                [
                                    'name' => $json['name'],
                                    'uuid' => $json['uuid'],
                                    'local' => 0,
                                    'created_by' => $this->ACL->getUser()->id
                                ]
                            );

                            if (!$orgSave) {
                                if ($this->ParamHandler->isRest()) {
                                    return $this->RestResponse->saveFailResponse('Servers', 'edit', false, $this->Servers->Organisation->validationError, $this->response->getType());
                                } else {
                                    $this->Flash->error(__('Couldn\'t save the new organisation, are you sure that the uuid is in the correct format?.'));
                                }
                                $fail = true;
                                $server['external_name'] = $json['name'];
                                $server['external_uuid'] = $json['uuid'];
                            } else {
                                $server['remote_org_id'] = $this->Servers->Organisation->id;
                            }
                        }
                    }
                    if (empty(Configure::read('MISP.host_org_id')) || $data['Server']['remote_org_id'] != Configure::read('MISP.host_org_id')) {
                        $server['internal'] = 0;
                    }
                }
            }
            if (!$fail) {
                // Save the data
                $this->Servers->patchEntity($server, $data['Server'], ['fieldList' => $fieldList]);
                if ($this->Servers->save($server)) {
                    if (isset($data['Server']['submitted_cert']) && (!isset($data['Server']['delete_cert']) || !$data['Server']['delete_cert'])) {
                        $this->__saveCert($data, $server->id, false);
                    } else {
                        if (isset($data['Server']['delete_cert']) && $data['Server']['delete_cert']) {
                            $this->__saveCert($data, $server->id, false, true);
                        }
                    }
                    if (isset($data['Server']['submitted_client_cert']) && (!isset($data['Server']['delete_client_cert']) || !$data['Server']['delete_client_cert'])) {
                        $this->__saveCert($data, $server->id, true);
                    } else {
                        if (isset($data['Server']['delete_client_cert']) && $data['Server']['delete_client_cert']) {
                            $this->__saveCert($data, $server->id, true, true);
                        }
                    }
                    if ($this->ParamHandler->isRest()) {
                        $server = $this->Servers->get($server->id);
                        return $this->RestResponse->viewData($server, $this->response->getType());
                    } else {
                        $this->Flash->success(__('The server has been saved'));
                        $this->redirect(['action' => 'index']);
                    }
                } else {
                    if ($this->ParamHandler->isRest()) {
                        return $this->RestResponse->saveFailResponse('Servers', 'edit', false, $this->Servers->validationError, $this->response->getType());
                    } else {
                        $this->Flash->error(__('The server could not be saved. Please, try again.'));
                    }
                }
            }
        } else {
            $this->Servers->read(null, $id);
            $server = $this->Servers->get($id);
            $server['authkey'] = '';
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->describe('Servers', 'edit', false, $this->response->getType());
        } else {
            $organisationOptions = [0 => 'Local organisation', 1 => 'External organisation', 2 => 'New external organisation'];

            $temp = $this->Servers->Organisations->find(
                'all',
                [
                    'fields' => ['id', 'name', 'local'],
                    'order' => ['lower(Organisation.name) ASC']
                ]
            );
            $allOrgs = [];
            $localOrganisations = [];
            $externalOrganisations = [];
            foreach ($temp as $o) {
                if ($o['Organisation']['local']) {
                    $localOrganisations[$o['Organisation']['id']] = $o['Organisation']['name'];
                } else {
                    $externalOrganisations[$o['Organisation']['id']] = $o['Organisation']['name'];
                }
                $allOrgs[] = ['id' => $o['Organisation']['id'], 'name' => $o['Organisation']['name']];
            }

            $allTypes = $this->Servers->getAllTypes();

            $oldRemoteSetting = 0;
            if (!$server['RemoteOrg']['local']) {
                $oldRemoteSetting = 1;
            }
            $this->set('host_org_id', Configure::read('MISP.host_org_id'));
            $this->set('oldRemoteSetting', $oldRemoteSetting);
            $this->set('oldRemoteOrg', $this->Servers->data['RemoteOrg']['id']);

            $this->set('organisationOptions', $organisationOptions);
            $this->set('localOrganisations', $localOrganisations);
            $this->set('externalOrganisations', $externalOrganisations);
            $this->set('allOrganisations', $allOrgs);

            $this->set('allTags', $this->__getTags());
            $this->set('allAttributeTypes', $allTypes['attribute']);
            $this->set('allObjectTypes', $allTypes['object']);
            $this->set('server', $server);
            $this->set('id', $id);
            $this->set('host_org_id', Configure::read('MISP.host_org_id'));
            $this->set('pull_scope', 'server');
        }
    }

    public function delete($id = null)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint expects POST requests.'));
        }
        $server = $this->Servers->get($id);
        if (!$server) {
            throw new NotFoundException(__('Invalid server'));
        }
        if ($this->Servers->delete($server)) {
            $message = __('Server deleted');
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Servers', 'delete', $message, $this->response->getType());
            } else {
                $this->Flash->success($message);
                $this->redirect(['controller' => 'servers', 'action' => 'index']);
            }
        }
        $message = __('Server was not deleted');
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveFailResponse('Servers', 'delete', $id, $message, $this->response->getType());
        } else {
            $this->Flash->error($message);
            $this->redirect(['action' => 'index']);
        }
    }

    public function eventBlockRule()
    {
        $AdminSettingsTable = $this->fetchTable('AdminSettings');

        $setting = $AdminSettingsTable->find(
            'all',
            [
                'conditions' => ['setting' => 'eventBlockRule'],
                'recursive' => -1
            ]
        )->first();
        if (empty($setting)) {
            $setting = ['setting' => 'eventBlockRule'];
            if ($this->request->is('post')) {
                $AdminSettingsTable->create();
            }
        }
        if ($this->request->is('post')) {
            $data = $this->request->getData();
            if (!empty($data['Server'])) {
                $data = $data['Server'];
            }
            $setting['AdminSetting']['setting'] = 'eventBlockRule';
            $setting['AdminSetting']['value'] = $data['value'];
            $settingEntity = $AdminSettingsTable->newEntity($setting);
            $result = $AdminSettingsTable->save($settingEntity);
            if ($result) {
                $message = __('Settings saved');
            } else {
                $message = __('Could not save the settings. Invalid input.');
            }
            if ($this->ParamHandler->isRest()) {
                if ($result) {
                    return $this->RestResponse->saveFailResponse('Servers', 'eventBlockRule', false, $message, $this->response->getType());
                } else {
                    return $this->RestResponse->saveSuccessResponse('Servers', 'eventBlockRule', $message, $this->response->getType());
                }
            } else {
                if ($result) {
                    $this->Flash->success($message);
                    $this->redirect('/');
                } else {
                    $this->Flash->error($message);
                }
            }
        }
        $this->set('setting', $setting);
    }

    /**
     * Pull one or more events with attributes from a remote instance.
     * Set $technique to
     *      full - download everything
     *      incremental - only new events
     *      <int>   - specific id of the event to pull
     */
    public function pull($id = null, $technique = 'full')
    {
        if (empty($id)) {
            if (!empty($this->request->getData()['id'])) {
                $id = $this->request->getData()['id'];
            } else {
                throw new NotFoundException(__('Invalid server'));
            }
        }

        $s = $this->Servers->get($id);
        if (empty($s)) {
            throw new NotFoundException(__('Invalid server'));
        }
        $error = false;

        if (false == $s['pull'] && ($technique === 'full' || $technique === 'incremental')) {
            $error = __('Pull setting not enabled for this server.');
        }
        if (false == $s['pull_galaxy_clusters'] && ($technique === 'pull_relevant_clusters')) {
            $error = __('Pull setting not enabled for this server.');
        }
        if (empty($error)) {
            if (!Configure::read('BackgroundJobs.enabled')) {
                $result = $this->Servers->pull($this->ACL->getUser()->toArray(), $technique, $s->toArray());
                if (is_array($result)) {
                    $success = __('Pull completed. {0} events pulled, {1} events could not be pulled, {2} proposals pulled, {3} sightings pulled, {4} clusters pulled.', count($result[0]), count($result[1]), $result[2], $result[3], $result[4]);
                } else {
                    $error = $result;
                }
                $this->set('successes', $result[0]);
                $this->set('fails', $result[1]);
                $this->set('pulledProposals', $result[2]);
                $this->set('pulledSightings', $result[3]);
            } else {
                /** @var JobsTable $JobsTable */
                $JobsTable = $this->fetchTable('Jobs');
                $jobId = $JobsTable->createJob(
                    $this->ACL->getUser(),
                    Job::WORKER_DEFAULT,
                    'pull',
                    'Server: ' . $id,
                    __('Pulling.')
                );

                $this->Servers->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::DEFAULT_QUEUE,
                    BackgroundJobsTool::CMD_SERVER,
                    [
                        'pull',
                        $this->ACL->getUser()->id,
                        $id,
                        $technique,
                        $jobId
                    ],
                    false,
                    $jobId
                );

                $success = __('Pull queued for background execution. Job ID: {0}', $jobId);
            }
        }
        if ($this->ParamHandler->isRest()) {
            if (!empty($error)) {
                return $this->RestResponse->saveFailResponse('Servers', 'pull', $id, $error, $this->response->getType());
            } else {
                return $this->RestResponse->saveSuccessResponse('Servers', 'pull', $id, $this->response->getType(), $success);
            }
        } else {
            if (!empty($error)) {
                $this->Flash->error($error);
                $this->redirect(['action' => 'index']);
            } else {
                $this->Flash->success($success);
                $this->redirect($this->referer());
            }
        }
    }

    public function push($id = null, $technique = false)
    {
        if (!empty($id)) {
            $this->Servers->id = $id;
        } else if (!empty($this->request->getData()['id'])) {
            $this->Servers->id = $this->request->getData()['id'];
        } else {
            throw new NotFoundException(__('Invalid server'));
        }
        if (!empty($this->request->getData()['technique'])) {
            $technique = $this->request->getData()['technique'];
        }
        if (!$this->Servers->exists()) {
            throw new NotFoundException(__('Invalid server'));
        }
        $s = $this->Servers->read(null, $id);

        if (!Configure::read('BackgroundJobs.enabled')) {
            $HttpSocket = new HttpTool();
            $HttpSocket->configFromServer($s);
            $result = $this->Servers->push($id, $technique, false, $HttpSocket, $this->ACL->getUser());
            if ($result === false) {
                $error = __('The remote server is too outdated to initiate a push towards it. Please notify the hosting organisation of the remote instance.');
            } elseif (!is_array($result)) {
                $error = $result;
            }
            if (!empty($error)) {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Servers', 'push', false, $error, $this->response->getType());
                } else {
                    $this->Flash->info($error);
                    $this->redirect(['action' => 'index']);
                }
            }
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Servers', 'push', $id, $this->response->getType(), __('Push complete. %s events pushed, %s events could not be pushed.', count($result[0]), count($result[1])));
            } else {
                $this->set('successes', $result[0]);
                $this->set('fails', $result[1]);
            }
        } else {
            /** @var JobsTable $JobsTable */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $this->ACL->getUser(),
                Job::WORKER_DEFAULT,
                'push',
                'Server: ' . $id,
                __('Pushing.')
            );

            $this->Servers->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                [
                    'push',
                    $this->ACL->getUser()->id,
                    $id,
                    $technique,
                    $jobId
                ],
                false,
                $jobId
            );

            $message = sprintf(__('Push queued for background execution. Job ID: %s'), $jobId);

            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Servers', 'push', $message, $this->response->getType());
            }
            $this->Flash->success($message);
            $this->redirect(['action' => 'index']);
        }
    }

    private function __saveCert($server, $id, $client = false, $delete = false)
    {
        if ($client) {
            $subm = 'submitted_client_cert';
            $attr = 'client_cert_file';
            $ins  = '_client';
        } else {
            $subm = 'submitted_cert';
            $attr = 'cert_file';
            $ins  = '';
        }
        if (!$delete) {
            $ext = '';
            if (isset($server[$subm]['name'])) {
                if ($this->request->getData()[$subm]['size'] != 0) {
                    if (!$this->Servers->checkFilename($server[$subm]['name'])) {
                        throw new Exception(__('Filename not allowed'));
                    }

                    if (!is_uploaded_file($server[$subm]['tmp_name'])) {
                        throw new Exception(__('File not uploaded correctly'));
                    }

                    $ext = pathinfo($server[$subm]['name'], PATHINFO_EXTENSION);
                    if (!in_array($ext, HttpTool::ALLOWED_CERT_FILE_EXTENSIONS)) {
                        $this->Flash->error(__('Invalid extension.'));
                        $this->redirect(['action' => 'index']);
                    }

                    if (!$server[$subm]['size'] > 0) {
                        $this->Flash->error(__('Incorrect extension or empty file.'));
                        $this->redirect(['action' => 'index']);
                    }

                    // read certificate file data
                    $certData = FileAccessTool::readFromFile($server[$subm]['tmp_name'], $server[$subm]['size']);
                } else {
                    return true;
                }
            } else {
                $ext = 'pem';
                $certData = base64_decode($server[$subm]);
            }

            // check if the file is a valid x509 certificate
            try {
                $cert = openssl_x509_parse($certData);
                if (!$cert) {
                    throw new Exception(__('Invalid certificate.'));
                }
            } catch (Exception $e) {
                $this->Flash->error(__('Invalid certificate.'));
                $this->redirect(['action' => 'index']);
            }

            $destpath = APP . "files" . DS . "certs" . DS;

            FileAccessTool::writeToFile($destpath . $id . $ins . '.' . $ext, $certData);
            $s = $this->Servers->get($id);
            $s[$attr] = $s['id'] . $ins . '.' . $ext;
            $this->Servers->save($s);
        } else {
            $s = $this->Servers->get($id);
            $s[$attr] = '';
            $this->Servers->save($s);
        }
        return true;
    }

    public function serverSettingsReloadSetting($setting, $id)
    {
        $pathToSetting = explode('.', $setting);
        if (
            strpos($setting, 'Plugin.Enrichment') !== false ||
            strpos($setting, 'Plugin.Import') !== false ||
            strpos($setting, 'Plugin.Export') !== false ||
            strpos($setting, 'Plugin.Cortex') !== false ||
            strpos($setting, 'Plugin.Action') !== false ||
            strpos($setting, 'Plugin.Workflow') !== false
        ) {
            $settingObject = $this->Servers->getCurrentServerSettings();
        } else {
            $settingObject = $this->Servers->serverSettings;
        }
        foreach ($pathToSetting as $key) {
            if (!isset($settingObject[$key])) {
                throw new MethodNotAllowedException();
            }
            $settingObject = $settingObject[$key];
        }
        $result = $this->Servers->serverSettingReadSingle($settingObject, $setting, $key);
        $this->set('setting', $result);
        $priorityErrorColours = [0 => 'red', 1 => 'yellow', 2 => 'green'];
        $this->set('priorityErrorColours', $priorityErrorColours);
        $priorities = [0 => 'Critical', 1 => 'Recommended', 2 => 'Optional', 3 => 'Deprecated'];
        $this->set('priorities', $priorities);
        $this->set('k', $id);
        $this->layout = false;

        $subGroup = 'general';
        if ($pathToSetting[0] === 'Plugin') {
            $subGroup = explode('_', $pathToSetting[1])[0];
        }
        $this->set('subGroup', $subGroup);

        $this->render('/Elements/healthElements/settings_row');
    }

    public function serverSettings($tab = false)
    {
        if (!$this->request->is('get')) {
            throw new MethodNotAllowedException('Just GET method is allowed.');
        }
        $tabs = [
            'MISP' => ['count' => 0, 'errors' => 0, 'severity' => 5],
            'Encryption' => ['count' => 0, 'errors' => 0, 'severity' => 5],
            'Proxy' => ['count' => 0, 'errors' => 0, 'severity' => 5],
            'Security' => ['count' => 0, 'errors' => 0, 'severity' => 5],
            'Plugin' => ['count' => 0, 'errors' => 0, 'severity' => 5],
            'SimpleBackgroundJobs' => ['count' => 0, 'errors' => 0, 'severity' => 5]
        ];

        $writeableErrors = [0 => __('OK'), 1 => __('not found'), 2 => __('is not writeable')];
        $readableErrors = [0 => __('OK'), 1 => __('not readable')];
        $gpgErrors = [0 => __('OK'), 1 => __('FAIL: settings not set'), 2 => __('FAIL: Failed to load GnuPG'), 3 => __('FAIL: Issues with the key/passphrase'), 4 => __('FAIL: sign failed')];
        $proxyErrors = [0 => __('OK'), 1 => __('not configured (so not tested)'), 2 => __('Getting URL via proxy failed')];
        $zmqErrors = [0 => __('OK'), 1 => __('not enabled (so not tested)'), 2 => __('Python ZeroMQ library not installed correctly.'), 3 => __('ZeroMQ script not running.')];
        $sessionErrors = [
            0 => __('OK'),
            1 => __('Too many expired sessions in the database, please clear the expired sessions'),
            2 => __('PHP session handler is using the default file storage. This is not recommended, please use the redis or database storage'),
            8 => __('Alternative setting used'),
            9 => __('Test failed')
        ];
        $moduleErrors = [0 => __('OK'), 1 => __('System not enabled'), 2 => __('No modules found')];
        $backgroundJobsErrors = [
            0 => __('OK'),
            1 => __('Not configured (so not tested)'),
            2 => __('Error connecting to Redis.'),
            3 => __('Error connecting to Supervisor.'),
            4 => __('Error connecting to Redis and Supervisor.')
        ];

        $finalSettings = $this->Servers->serverSettingsRead();
        $issues = [
            'errors' => [
                0 => [
                    'value' => 0,
                    'description' => __('MISP will not operate correctly or will be unsecure until these issues are resolved.')
                ],
                1 => [
                    'value' => 0,
                    'description' => __('Some of the features of MISP cannot be utilised until these issues are resolved.')
                ],
                2 => [
                    'value' => 0,
                    'description' => __('There are some optional tweaks that could be done to improve the looks of your MISP instance.')
                ],
            ],
            'deprecated' => [],
            'overallHealth' => 3,
        ];
        $dumpResults = [];
        $tempArray = [];
        foreach ($finalSettings as $k => $result) {
            if ($result['level'] == 3) {
                $issues['deprecated']++;
            }
            $tabs[$result['tab']]['count']++;
            if (isset($result['error']) && $result['level'] < 3) {
                $issues['errors'][$result['level']]['value']++;
                if ($result['level'] < $issues['overallHealth']) {
                    $issues['overallHealth'] = $result['level'];
                }
                $tabs[$result['tab']]['errors']++;
                if ($result['level'] < $tabs[$result['tab']]['severity']) {
                    $tabs[$result['tab']]['severity'] = $result['level'];
                }
            }
            if (isset($result['optionsSource']) && is_callable($result['optionsSource'])) {
                $result['options'] = $result['optionsSource']();
            }
            $dumpResults[] = $result;
            if ($result['tab'] == $tab) {
                if (isset($result['subGroup'])) {
                    $tempArray[$result['subGroup']][] = $result;
                } else {
                    $tempArray['general'][] = $result;
                }
            }
        }
        $finalSettings = $tempArray;
        // Diagnostics portion
        $diagnostic_errors = 0;
        if ($tab === 'correlations') {
            $CorrelationsTable = $this->fetchTable('Correlations');
            $correlation_metrics = $CorrelationsTable->collectMetrics();
            $this->set('correlation_metrics', $correlation_metrics);
        }
        if ($tab === 'files') {
            if (!empty(Configure::read('Security.disable_instance_file_uploads'))) {
                throw new MethodNotAllowedException(__('This functionality is disabled.'));
            }
            $files = $this->Servers->grabFiles();
            $this->set('files', $files);
        }
        // Only run this check on the diagnostics tab
        if ($tab === 'diagnostics' || $tab === 'download' || $this->ParamHandler->isRest()) {
            $php_ini = php_ini_loaded_file();
            $this->set('php_ini', $php_ini);

            $attachmentTool = new AttachmentTool();
            try {
                $advanced_attachments = $attachmentTool->checkAdvancedExtractionStatus();
            } catch (Exception $e) {
                $this->log($e->getMessage(), LOG_NOTICE);
                $advanced_attachments = false;
            }

            $this->set('advanced_attachments', $advanced_attachments);

            $gitStatus = $this->Servers->getCurrentGitStatus(true);
            $this->set('branch', $gitStatus['branch']);
            $this->set('commit', $gitStatus['commit']);
            $this->set('latestCommit', $gitStatus['latestCommit']);
            $this->set('version', $gitStatus['version']);

            $phpSettings = [
                'max_execution_time' => [
                    'explanation' => 'The maximum duration that a script can run (does not affect the background workers). A too low number will break long running scripts like comprehensive API exports',
                    'recommended' => 300,
                    'unit' => 'seconds',
                ],
                'memory_limit' => [
                    'explanation' => 'The maximum memory that PHP can consume. It is recommended to raise this number since certain exports can generate a fair bit of memory usage',
                    'recommended' => 2048,
                    'unit' => 'MB'
                ],
                'upload_max_filesize' => [
                    'explanation' => 'The maximum size that an uploaded file can be. It is recommended to raise this number to allow for the upload of larger samples',
                    'recommended' => 50,
                    'unit' => 'MB'
                ],
                'post_max_size' => [
                    'explanation' => 'The maximum size of a POSTed message, this has to be at least the same size as the upload_max_filesize setting',
                    'recommended' => 50,
                    'unit' => 'MB'
                ]
            ];

            foreach ($phpSettings as $setting => $settingArray) {
                $phpSettings[$setting]['value'] = $this->Servers->getIniSetting($setting);
                if ($phpSettings[$setting]['value'] && $settingArray['unit'] && $settingArray['unit'] === 'MB') {
                    // convert basic unit to M
                    $phpSettings[$setting]['value'] = (int) floor($phpSettings[$setting]['value'] / 1024 / 1024);
                }
            }
            $this->set('phpSettings', $phpSettings);

            if ($gitStatus['version'] && $gitStatus['version']['upToDate'] === 'older') {
                $diagnostic_errors++;
            }

            // check if the STIX and Cybox libraries are working and the correct version using the test script stixtest.py
            $stix = $this->Servers->stixDiagnostics($diagnostic_errors);

            $yaraStatus = $this->Servers->yaraDiagnostics($diagnostic_errors);

            // if GnuPG is set up in the settings, try to encrypt a test message
            $gpgStatus = $this->Servers->gpgDiagnostics($diagnostic_errors);

            // if the message queue pub/sub is enabled, check whether the extension works
            $zmqStatus = $this->Servers->zmqDiagnostics($diagnostic_errors);

            // if Proxy is set up in the settings, try to connect to a test URL
            $proxyStatus = $this->Servers->proxyDiagnostics($diagnostic_errors);

            // if SimpleBackgroundJobs is set up in the settings, try to connect to Redis
            $backgroundJobsStatus = $this->Servers->backgroundJobsDiagnostics($diagnostic_errors);

            // get the DB diagnostics
            $dbDiagnostics = $this->Servers->dbSpaceUsage();
            $dbSchemaDiagnostics = $this->Servers->dbSchemaDiagnostic();
            $dbConfiguration = $this->Servers->dbConfiguration();

            $redisInfo = $this->Servers->redisInfo();

            $moduleTypes = ['Enrichment', 'Import', 'Export', 'Cortex'];
            foreach ($moduleTypes as $type) {
                $moduleStatus[$type] = $this->Servers->moduleDiagnostics($diagnostic_errors, $type);
            }

            // get php session diagnostics
            $sessionStatus = $this->Servers->sessionDiagnostics($diagnostic_errors);

            $AttachmentScansTable = $this->fetchTable('AttachmentScans');
            try {
                $attachmentScan = ['status' => true, 'software' => $AttachmentScansTable->diagnostic()];
            } catch (Exception $e) {
                $attachmentScan = ['status' => false, 'error' => $e->getMessage()];
            }

            $securityAudit = (new SecurityAudit())->run($this->Server);

            $view = compact('gpgStatus', 'sessionErrors', 'proxyStatus', 'sessionStatus', 'zmqStatus', 'moduleStatus', 'yaraStatus', 'gpgErrors', 'proxyErrors', 'zmqErrors', 'stix', 'moduleErrors', 'moduleTypes', 'dbDiagnostics', 'dbSchemaDiagnostics', 'dbConfiguration', 'redisInfo', 'attachmentScan', 'securityAudit');
        } else {
            $view = [];
        }

        // check whether the files are writeable
        $writeableDirs = $this->Servers->writeableDirsDiagnostics($diagnostic_errors);
        $writeableFiles = $this->Servers->writeableFilesDiagnostics($diagnostic_errors);
        $readableFiles = $this->Servers->readableFilesDiagnostics($diagnostic_errors);
        $extensions = $this->Servers->extensionDiagnostics();

        // check if the encoding is not set to utf8
        $dbEncodingStatus = $this->Servers->databaseEncodingDiagnostics($diagnostic_errors);

        $view = array_merge($view, compact('diagnostic_errors', 'tabs', 'tab', 'issues', 'finalSettings', 'writeableErrors', 'readableErrors', 'writeableDirs', 'writeableFiles', 'readableFiles', 'extensions', 'dbEncodingStatus'));
        $this->set($view);

        $workerIssueCount = 4;
        $worker_array = [];
        if (Configure::read('BackgroundJobs.enabled')) {
            $workerIssueCount = 0;
            $worker_array = $this->Servers->workerDiagnostics($workerIssueCount);
        }
        $this->set('worker_array', $worker_array);
        if ($tab === 'download' || $this->ParamHandler->isRest()) {
            foreach ($dumpResults as $key => $dr) {
                unset($dumpResults[$key]['description']);
            }
            $dump = [
                'version' => $gitStatus['version'],
                'phpSettings' => $phpSettings,
                'gpgStatus' => $gpgErrors[$gpgStatus['status']],
                'proxyStatus' => $proxyErrors[$proxyStatus],
                'zmqStatus' => $zmqStatus,
                'stix' => $stix,
                'moduleStatus' => $moduleStatus,
                'writeableDirs' => $writeableDirs,
                'writeableFiles' => $writeableFiles,
                'readableFiles' => $readableFiles,
                'dbDiagnostics' => $dbDiagnostics,
                'dbSchemaDiagnostics' => $dbSchemaDiagnostics,
                'dbConfiguration' => $dbConfiguration,
                'redisInfo' => $redisInfo,
                'finalSettings' => $dumpResults,
                'extensions' => $extensions,
                'workers' => $worker_array,
                'backgroundJobsStatus' => $backgroundJobsErrors[$backgroundJobsStatus]
            ];
            foreach ($dump['finalSettings'] as $k => $v) {
                if (!empty($v['redacted'])) {
                    $dump['finalSettings'][$k]['value'] = '*****';
                }
            }
            $this->response->withStringBody(json_encode($dump, JSON_PRETTY_PRINT));
            $this->response->withType('json');
            $this->response->withDownload('MISP.report.json');
            return $this->response;
        }

        $priorities = [0 => 'Critical', 1 => 'Recommended', 2 => 'Optional', 3 => 'Deprecated'];
        $this->set('priorities', $priorities);
        $this->set('workerIssueCount', $workerIssueCount);
        $priorityErrorColours = [0 => 'red', 1 => 'yellow', 2 => 'green'];
        $this->set('priorityErrorColours', $priorityErrorColours);
        $this->set('phpversion', PHP_VERSION);
        $this->set('phpmin', $this->phpmin);
        $this->set('phprec', $this->phprec);
        $this->set('phptoonew', $this->phptoonew);
        $this->set('title_for_layout', __('Diagnostics'));
    }

    public function startWorker($type)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }

        if (Configure::read('BackgroundJobs.enabled')) {
            $message = __('Worker start signal sent');
            $this->Servers->getBackgroundJobsTool()->startWorkerByQueue($type);

            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Servers', 'startWorker', $type, $this->response->getType(), $message);
            } else {
                $this->Flash->info($message);
                $this->redirect('/servers/serverSettings/workers');
            }
        }

        // CakeResque
        $validTypes = ['default', 'email', 'scheduler', 'cache', 'prio', 'update'];
        if (!in_array($type, $validTypes)) {
            throw new MethodNotAllowedException('Invalid worker type.');
        }

        $prepend = '';
        if ($type != 'scheduler') {
            $workerIssueCount = 0;
            $workerDiagnostic = $this->Servers->workerDiagnostics($workerIssueCount);
            if ($type == 'update' && isset($workerDiagnostic['update']['ok']) && $workerDiagnostic['update']['ok']) {
                $message = __('Only one `update` worker can run at a time');
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Servers', 'startWorker', false, $message, $this->response->getType());
                } else {
                    $this->Flash->error($message);
                    $this->redirect('/servers/serverSettings/workers');
                }
            }
            shell_exec($prepend . APP . 'Console' . DS . 'cake CakeResque.CakeResque start --interval 5 --queue ' . $type . ' > /dev/null 2>&1 &');
        } else {
            shell_exec($prepend . APP . 'Console' . DS . 'cake CakeResque.CakeResque startscheduler -i 5 > /dev/null 2>&1 &');
        }
        $message = __('Worker start signal sent');
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Servers', 'startWorker', $type, $this->response->getType(), $message);
        } else {
            $this->Flash->info($message);
            $this->redirect('/servers/serverSettings/workers');
        }
    }

    public function stopWorker($pid)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }

        $message = __('Worker stop signal sent');

        if (Configure::read('BackgroundJobs.enabled')) {
            $this->Servers->getBackgroundJobsTool()->stopWorker($pid);
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->saveSuccessResponse('Servers', 'stopWorker', $pid, $this->response->getType(), $message);
            } else {
                $this->Flash->info($message);
                $this->redirect('/servers/serverSettings/workers');
            }
        }

        // CakeResque
        $this->Servers->killWorker($pid, $this->ACL->getUser());
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Servers', 'stopWorker', $pid, $this->response->getType(), $message);
        } else {
            $this->Flash->info($message);
            $this->redirect('/servers/serverSettings/workers');
        }
    }

    public function getWorkers()
    {
        if (Configure::read('BackgroundJobs.enabled')) {
            $workerIssueCount = 0;
            $worker_array = $this->Servers->workerDiagnostics($workerIssueCount);
        } else {
            $worker_array = [__('Background jobs not enabled')];
        }
        return $this->RestResponse->viewData($worker_array);
    }

    public function idTranslator($localId = null)
    {
        // We retrieve the list of remote servers that we can query
        $servers = $this->Servers->find(
            'all',
            [
                'conditions' => ['OR' => ['pull' => true, 'push' => true]],
                'recursive' => -1,
                'order' => ['Server.priority ASC'],
            ]
        );

        // We generate the list of servers for the dropdown
        $displayServers = [];
        foreach ($servers as $s) {
            $displayServers[] = [
                'name' => $s['Server']['name'],
                'value' => $s['Server']['id'],
            ];
        }
        $this->set('servers', $displayServers);

        if ($localId || $this->request->is('post')) {
            $data = $this->request->getData();
            if ($localId && $this->request->is('get')) {
                $data['Event']['local'] = 'local';
                $data['Event']['uuid'] = $localId;
            }
            $EventsTable = $this->fetchTable('Events');
            $remote_events = [];
            if (!empty($data['Event']['uuid']) && $data['Event']['local'] === "local") {
                $local_event = $EventsTable->fetchSimpleEvent($this->ACL->getUser(), $data['Event']['uuid']);
            } else if (!empty($data['Event']['uuid']) && $data['Event']['local'] === "remote" && !empty($data['Server']['id'])) {
                //We check on the remote server for any event with this id and try to find a match locally
                $conditions = ['AND' => ['Server.id' => $data['Server']['id'], 'Server.pull' => true]];
                $remote_server = $this->Servers->find('all', ['conditions' => $conditions])->first();
                if (!empty($remote_server)) {
                    try {
                        $remote_event = $EventsTable->downloadEventMetadataFromServer($data['Event']['uuid'], $remote_server);
                    } catch (Exception $e) {
                        $this->Flash->error(__("Issue while contacting the remote server to retrieve event information"));
                        return;
                    }

                    if (empty($remote_event)) {
                        $this->Flash->error(__("This event could not be found or you don't have permissions to see it."));
                        return;
                    }

                    $local_event = $EventsTable->fetchSimpleEvent($this->ACL->getUser(), $remote_event['uuid']);
                    // we record it to avoid re-querying the same server in the 2nd phase
                    if (!empty($local_event)) {
                        $remote_events[] = [
                            "server_id" => $remote_server['Server']['id'],
                            "server_name" => $remote_server['Server']['name'],
                            "url" => $remote_server['Server']['url'] . "/events/view/" . $remote_event['id'],
                            "remote_id" => $remote_event['id']
                        ];
                    }
                }
            }
            if (empty($local_event)) {
                $this->Flash->error(__("This event could not be found or you don't have permissions to see it."));
                return;
            } else {
                $this->Flash->success(__('The event has been found.'));
            }

            // In the second phase, we query all configured sync servers to get their info on the event
            foreach ($servers as $server) {
                // We check if the server was not already contacted in phase 1
                if (count($remote_events) > 0 && $remote_events[0]['server_id'] == $server['Server']['id']) {
                    continue;
                }

                $exception = null;
                try {
                    $remoteEvent = $EventsTable->downloadEventMetadataFromServer($local_event['Event']['uuid'], $server);
                } catch (Exception $e) {
                    $remoteEvent = null;
                    $exception = $e->getMessage();
                }
                $remoteEventId = isset($remoteEvent['id']) ? $remoteEvent['id'] : null;
                $remote_events[] = [
                    "server_id" => $server['Server']['id'],
                    "server_name" => $server['Server']['name'],
                    "url" => isset($remoteEventId) ? $server['Server']['url'] . "/events/view/" . $remoteEventId : $server['Server']['url'],
                    "remote_id" => isset($remoteEventId) ? $remoteEventId : false,
                    "exception" => $exception,
                ];
            }

            $this->set('local_event', $local_event);
            $this->set('remote_events', $remote_events);
        }
        $this->set('title_for_layout', __('Event ID translator'));
    }

    public function getSubmodulesStatus()
    {
        $this->set('submodules', $this->Servers->getSubmodulesGitStatus());
        $this->render('ajax/submoduleStatus');
    }

    public function getSetting($settingName)
    {
        $setting = $this->Servers->getSettingData($settingName);
        if (!$setting) {
            throw new NotFoundException(__('Setting %s is invalid.', $settingName));
        }
        if (!empty($setting["redacted"])) {
            throw new ForbiddenException(__('This setting is redacted.'));
        }
        if (Configure::check($settingName)) {
            $setting['value'] = Configure::read($settingName);
        }
        return $this->RestResponse->viewData($setting);
    }

    public function serverSettingsEdit($settingName, $id = false, $forceSave = false)
    {
        if (!$this->ParamHandler->isRest()) {
            if (!isset($id)) {
                throw new MethodNotAllowedException();
            }
            $this->set('id', $id);
        }
        $setting = $this->Servers->getSettingData($settingName);
        if ($setting === false) {
            throw new NotFoundException(__('Setting %s is invalid.', $settingName));
        }
        if (!empty($setting['cli_only'])) {
            throw new MethodNotAllowedException(__('This setting can only be edited via the CLI.'));
        }
        if ($this->request->is('get')) {
            $value = Configure::read($setting['name']);
            if (isset($value)) {
                $setting['value'] = $value;
            }
            $setting['setting'] = $setting['name'];
            if (isset($setting['optionsSource']) && is_callable($setting['optionsSource'])) {
                $setting['options'] = $setting['optionsSource']();
            }
            $subGroup = explode('.', $setting['name']);
            if ($subGroup[0] === 'Plugin') {
                $subGroup = explode('_', $subGroup[1])[0];
            } else {
                $subGroup = 'general';
            }
            if ($this->ParamHandler->isRest()) {
                if (!empty($setting['redacted'])) {
                    throw new ForbiddenException(__('This setting is redacted.'));
                }
                return $this->RestResponse->viewData([$setting['name'] => $setting['value']]);
            } else {
                $this->set('subGroup', $subGroup);
                $this->set('setting', $setting);
                $this->render('ajax/server_settings_edit');
            }
        } else if ($this->request->is('post')) {
            $data = $this->request->getData();
            if (!isset($data['Server'])) {
                $data = ['Server' => $data];
            }
            if (!isset($data['Server']['value']) || !is_scalar($data['Server']['value'])) {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, 'Invalid input. Expected: {"value": "new_setting"}', $this->response->getType());
                }
            }
            if (!empty($data['Server']['force'])) {
                $forceSave = $data['Server']['force'];
            }
            if (trim($data['Server']['value']) === '*****') {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, 'No change.', $this->response->getType());
                } else {
                    return new Response(['body' => json_encode(['saved' => false, 'errors' => 'No change.']), 'status' => 200, 'type' => 'json']);
                }
            }
            $this->autoRender = false;
            if (!Configure::read('MISP.system_setting_db') && !is_writeable(APP . 'Config/config.php')) {
                $LogsTable = $this->fetchTable('Logs');
                $LogsTable->saveOrFailSilently(
                    [
                        'org' => $this->ACL->getUser()['Organisation']['name'],
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => $this->ACL->getUser()->email,
                        'action' => 'serverSettingsEdit',
                        'user_id' => $this->ACL->getUser()->id,
                        'title' => 'Server setting issue',
                        'change' => 'There was an issue witch changing ' . $setting['name'] . ' to ' . $data['Server']['value']  . '. The error message returned is: app/Config.config.php is not writeable to the apache user. No changes were made.',
                    ]
                );
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, 'app/Config.config.php is not writeable to the apache user.', $this->response->getType());
                } else {
                    return new Response(['body' => json_encode(['saved' => false, 'errors' => 'app/Config.config.php is not writeable to the apache user.']), 'status' => 200, 'type' => 'json']);
                }
            }
            $result = $this->Servers->serverSettingsEditValue($this->ACL->getUser(), $setting, $data['Server']['value'], $forceSave);
            if ($result === true) {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Servers', 'serverSettingsEdit', false, $this->response->getType(), 'Field updated');
                } else {
                    return new Response(['body' => json_encode(['saved' => true, 'success' => 'Field updated.']), 'status' => 200, 'type' => 'json']);
                }
            } else {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Servers', 'serverSettingsEdit', false, $result, $this->response->getType());
                } else {
                    return new Response(['body' => json_encode(['saved' => false, 'errors' => $result]), 'status' => 200, 'type' => 'json']);
                }
            }
        }
    }

    public function killAllWorkers($force = false)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->Servers->killAllWorkers($this->ACL->getUser(), $force);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Server', 'killAllWorkers', false, $this->response->getType(), __('Killing workers.'));
        }
        $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'workers']);
    }

    public function restartWorkers()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }

        if (Configure::read('SimpleBackgroundJobs.enabled')) {
            $this->Servers->getBackgroundJobsTool()->restartWorkers();
        } else {
            // CakeResque
            $this->Servers->restartWorkers($this->ACL->getUser());
        }

        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Server', 'restartWorkers', false, $this->response->getType(), __('Restarting workers.'));
        }
        $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'workers']);
    }

    public function restartDeadWorkers()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }

        if (Configure::read('SimpleBackgroundJobs.enabled')) {
            $this->Servers->getBackgroundJobsTool()->restartDeadWorkers();
        } else {
            // CakeResque
            $this->Servers->restartDeadWorkers($this->ACL->getUser());
        }

        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Server', 'restartDeadWorkers', false, $this->response->getType(), __('Restarting workers.'));
        }
        $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'workers']);
    }

    public function deleteFile($type, $filename)
    {
        if ($this->request->is('post')) {
            $validItems = $this->Servers->getFileRules();
            $existingFile = new SplFileInfo($validItems[$type]['path'] . DS . $filename);
            if (!$existingFile->isFile()) {
                $this->Flash->error(__('File not found.', true), 'default', [], 'error');
                $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'files']);
            }
            if (FileAccessTool::deleteFile($existingFile->getPathname())) {
                $this->Flash->success('File deleted.');
            } else {
                $this->Flash->error(__('File could not be deleted.', true), 'default', [], 'error');
            }
            $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'files']);
        } else {
            throw new MethodNotAllowedException('This action expects a POST request.');
        }
    }

    public function uploadFile($type)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        if (!empty(Configure::read('Security.disable_instance_file_uploads'))) {
            throw new MethodNotAllowedException(__('Feature disabled.'));
        }
        $validItems = $this->Servers->getFileRules();

        // Check if there were problems with the file upload
        // only keep the last part of the filename, this should prevent directory attacks
        $data = $this->request->getData();
        $filename = basename($data['Server']['file']['name']);
        if (!preg_match("/" . $validItems[$type]['regex'] . "/", $filename)) {
            $this->Flash->error($validItems[$type]['regex_error'], 'default', [], 'error');
            $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'files']);
        }
        if (empty($data['Server']['file']['tmp_name']) || !is_uploaded_file($data['Server']['file']['tmp_name'])) {
            $this->Flash->error(__('Upload failed.', true), 'default', [], 'error');
            $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'files']);
        }

        // check if the file already exists
        $existingFile = new SplFileInfo($validItems[$type]['path'] . DS . $filename);
        if ($existingFile->isFile()) {
            $this->Flash->info(__('File already exists. If you would like to replace it, remove the old one first.', true), 'default', [], 'error');
            $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'files']);
        }

        $result = move_uploaded_file($data['Server']['file']['tmp_name'], $validItems[$type]['path'] . DS . $filename);
        if ($result) {
            $this->Flash->success('File uploaded.');
        } else {
            $this->Flash->error(__('Upload failed.', true), 'default', [], 'error');
        }
        $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'files']);
    }

    public function fetchServersForSG($idList = '{}')
    {
        $id_exclusion_list = json_decode($idList, true);
        $temp = $this->Servers->find(
            'all',
            [
                'conditions' => [
                    'id !=' => $id_exclusion_list,
                ],
                'recursive' => -1,
                'fields' => ['id', 'name', 'url']
            ]
        );
        $servers = [];
        foreach ($temp as $server) {
            $servers[] = ['id' => $server['Server']['id'], 'name' => $server['Server']['name'], 'url' => $server['Server']['url']];
        }
        $this->layout = false;
        $this->autoRender = false;
        $this->set('servers', $servers);
        $this->render('ajax/fetch_servers_for_sg');
    }

    public function postTest()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('Invalid request, expecting a POST request.');
        }
        // Fix for PHP-FPM / Nginx / etc
        // Fix via https://www.popmartian.com/tipsntricks/2015/07/14/howto-use-php-getallheaders-under-fastcgi-php-fpm-nginx-etc/
        if (!function_exists('getallheaders')) {
            $headers = [];
            foreach ($_SERVER as $name => $value) {
                $name = strtolower($name);
                if (substr($name, 0, 5) === 'http_') {
                    $headers[str_replace('_', '-', substr($name, 5))] = $value;
                }
            }
        } else {
            $headers = getallheaders();
            $headers = array_change_key_case($headers, CASE_LOWER);
        }
        $result = [
            'body' => $this->request->getData(),
            'headers' => [
                'Content-type' => isset($headers['content-type']) ? $headers['content-type'] : 0,
                'Accept' => isset($headers['accept']) ? $headers['accept'] : 0,
                'Authorization' => isset($headers['authorization']) ? 'OK' : 0,
            ],
        ];
        return $this->RestResponse->viewData($result, 'json');
    }

    public function getRemoteUser($id)
    {
        $user = $this->Servers->getRemoteUser($id);
        if ($user === null) {
            throw new NotFoundException(__('Invalid server'));
        }
        return $this->RestResponse->viewData($user);
    }

    public function testConnection($id = false)
    {
        $server = $this->Servers->get($id);
        if (!$server) {
            throw new NotFoundException(__('Invalid server'));
        }
        $result = $this->Servers->runConnectionTest($server->toArray());
        if ($result['status'] == 1) {
            if (isset($result['info']['version']) && preg_match('/^[0-9]+\.+[0-9]+\.[0-9]+$/', $result['info']['version'])) {
                $perm_sync = isset($result['info']['perm_sync']) ? $result['info']['perm_sync'] : false;
                $perm_sighting = isset($result['info']['perm_sighting']) ? $result['info']['perm_sighting'] : false;
                $local_version = $this->Servers->checkMISPVersion();
                $version = explode('.', $result['info']['version']);
                $mismatch = false;
                $newer = false;
                $parts = ['major', 'minor', 'hotfix'];
                foreach ($parts as $k => $v) {
                    if (!$mismatch) {
                        if ($version[$k] > $local_version[$v]) {
                            $mismatch = $v;
                            $newer = 'remote';
                        } elseif ($version[$k] < $local_version[$v]) {
                            $mismatch = $v;
                            $newer = 'local';
                        }
                    }
                }
                if (!$mismatch && $version[0] == 2 && $version[2] < 111) {
                    $mismatch = 'proposal';
                }
                if (!$perm_sync && !$perm_sighting) {
                    $result['status'] = 7;
                    return new Response(['body' => json_encode($result), 'type' => 'json']);
                }
                if (!$perm_sync && $perm_sighting) {
                    $result['status'] = 8;
                    return new Response(['body' => json_encode($result), 'type' => 'json']);
                }
                return $this->RestResponse->viewData(
                    [
                        'status' => 1,
                        'local_version' => implode('.', $local_version),
                        'version' => implode('.', $version),
                        'mismatch' => $mismatch,
                        'newer' => $newer,
                        'post' => isset($result['post']) ? $result['post']['status'] : 'too old',
                        'response_encoding' => isset($result['post']['content-encoding']) ? $result['post']['content-encoding'] : null,
                        'request_encoding' => isset($result['info']['request_encoding']) ? $result['info']['request_encoding'] : null,
                        'client_certificate' => $result['client_certificate'],
                    ],
                    'json'
                );
            } else {
                $result['status'] = 3;
            }
        }
        return new Response(['body' => json_encode($result), 'type' => 'json']);
    }

    public function startZeroMQServer()
    {
        $pubSubTool = $this->Servers->getPubSubTool();
        $result = $pubSubTool->restartServer();
        if ($result === true) {
            return new Response(['body' => json_encode(['saved' => true, 'success' => 'ZeroMQ server successfully started.']), 'status' => 200, 'type' => 'json']);
        } else {
            return new Response(['body' => json_encode(['saved' => false, 'errors' => $result]), 'status' => 200, 'type' => 'json']);
        }
    }

    public function stopZeroMQServer()
    {
        $pubSubTool = $this->Servers->getPubSubTool();
        $result = $pubSubTool->killService();
        if ($result === true) {
            return new Response(['body' => json_encode(['saved' => true, 'success' => 'ZeroMQ server successfully killed.']), 'status' => 200, 'type' => 'json']);
        } else {
            return new Response(['body' => json_encode(['saved' => false, 'errors' => 'Could not kill the previous instance of the ZeroMQ script.']), 'status' => 200, 'type' => 'json']);
        }
    }

    public function statusZeroMQServer()
    {
        $pubSubTool = $this->Servers->getPubSubTool();
        $result = $pubSubTool->statusCheck();
        if (!empty($result)) {
            $this->set('events', $result['publishCount']);
            $this->set('messages', $result['messageCount']);
            $this->set('time', $result['timestamp']);
            $this->set('time2', $result['timestampSettings']);
        }
        $this->render('ajax/zeromqstatus');
    }

    public function purgeSessions()
    {
        if ($this->Servers->updateDatabase('cleanSessionTable') == false) {
            $this->Flash->error('Could not purge the session table.');
        }
        $this->redirect('/servers/serverSettings/diagnostics');
    }

    public function clearWorkerQueue($worker)
    {
        if (!$this->request->is('Post') || $this->request->is('ajax')) {
            throw new MethodNotAllowedException();
        }

        if (Configure::read('SimpleBackgroundJobs.enabled')) {
            $this->Servers->getBackgroundJobsTool()->purgeQueue($worker);
        } else {
            // CakeResque
            $worker_array = ['cache', 'default', 'email', 'prio'];
            if (!in_array($worker, $worker_array)) {
                throw new MethodNotAllowedException('Invalid worker');
            }
            $redis = RedisTool::init();
            $redis->del('queue:' . $worker);
        }

        $this->Flash->success('Queue cleared.');
        $this->redirect($this->referer());
    }

    public function getVersion()
    {
        $user = $this->ACL->getUser();
        $versionArray = $this->Servers->checkMISPVersion();
        $response = [
            'version' => $versionArray['major'] . '.' . $versionArray['minor'] . '.' . $versionArray['hotfix'],
            'pymisp_recommended_version' => $this->pyMispVersion,
            'perm_sync' => (bool) $user['Role']['perm_sync'],
            'perm_sighting' => (bool) $user['Role']['perm_sighting'],
            'perm_galaxy_editor' => (bool) $user['Role']['perm_galaxy_editor'],
            'request_encoding' => $this->CompressedRequestHandler->supportedEncodings(),
            'filter_sightings' => true, // check if Sightings::filterSightingUuidsForPush method is supported
        ];
        return $this->RestResponse->viewData($response, 'json');
    }

    /**
     * @deprecated Use field `pymisp_recommended_version` from getVersion instead
     */
    public function getPyMISPVersion()
    {
        $this->set('response', ['version' => $this->pyMispVersion]);
        $this->set('_serialize', 'response');
    }

    public function checkout()
    {
        $result = $this->Servers->checkoutMain();
    }

    public function update($branch = false)
    {
        if ($this->request->is('post')) {
            $filterData = [
                'request' => $this->request,
                'named_params' => $this->params['named'],
                'paramArray' => ['branch'],
                'ordered_url_params' => [],
                'additional_delimiters' => PHP_EOL
            ];
            $exception = false;
            $settings = $this->harvestParameters($filterData, $exception);
            $status = $this->Servers->getCurrentGitStatus();
            $raw = [];
            if (empty($status['branch'])) { // do not try to update if you are not on branch
                $msg = 'Update failed, you are not on branch';
                $raw[] = $msg;
                $update = $msg;
            } else {
                if ($settings === false) {
                    $settings = [];
                }
                $update = $this->Servers->update($status, $raw, $settings);
            }
            if ($this->ParamHandler->isRest()) {
                return $this->RestResponse->viewData(['results' => $raw], $this->response->getType());
            } else {
                return new Response(['body' => $update, 'type' => 'txt']);
            }
        } else {
            $this->set('isUpdatePossible', $this->Servers->isUpdatePossible());
            $this->set('branch', $this->Servers->getCurrentBranch());
            $this->render('ajax/update');
        }
    }

    public function ondemandAction()
    {
        $AdminSettingsTable = $this->fetchTable('AdminSettings');
        $actions = $this->Servers->actions_description;
        $default_fields = [
            'title' => '',
            'description' => '',
            'liveOff' => false,
            'recommendBackup' => false,
            'exitOnError' => false,
            'requirements' => '',
            'url' => $this->baseurl . '/'
        ];
        foreach ($actions as $id => $action) {
            foreach ($default_fields as $field => $value) {
                if (!isset($action[$field])) {
                    $actions[$id][$field] = $value;
                }
            }
            $done = $AdminSettingsTable->getSetting($id);
            $actions[$id]['done'] = ($done == '1');
        }
        $this->set('actions', $actions);
        $this->set('updateLocked', $this->Servers->isUpdateLocked());
    }

    public function getSubmoduleQuickUpdateForm($submodule_path = false)
    {
        $this->set('submodule', base64_decode($submodule_path));
        $this->render('ajax/submodule_quick_update_form');
    }

    public function updateSubmodule()
    {
        if ($this->request->is('post')) {
            $request = $this->request->getData();
            $submodule = $request['Server']['submodule'];
            $res = $this->Servers->updateSubmodule($this->ACL->getUser(), $submodule);
            return new Response(['body' => json_encode($res), 'type' => 'json']);
        } else {
            throw new MethodNotAllowedException();
        }
    }

    public function getInstanceUUID()
    {
        return $this->RestResponse->viewData(['uuid' => Configure::read('MISP.uuid')], $this->response->getType());
    }

    public function cache($id = 'all')
    {
        if (Configure::read('BackgroundJobs.enabled')) {
            /** @var JobsTable $JobsTable */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $this->ACL->getUser(),
                Job::WORKER_DEFAULT,
                'cache_servers',
                intval($id) ? $id : 'all',
                __('Starting server caching.')
            );

            $this->Servers->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                [
                    'cacheServer',
                    $this->ACL->getUser()->id,
                    $id,
                    $jobId
                ],
                false,
                $jobId
            );

            $message = 'Server caching job initiated.';
        } else {
            $result = $this->Servers->cacheServerInitiator($this->ACL->getUser(), $id);
            if (!$result) {
                $this->Flash->error(__('Caching the servers has failed.'));
                $this->redirect(['action' => 'index']);
            }
            $message = __('Caching the servers has successfully completed.');
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->saveSuccessResponse('Server', 'cache', false, $this->response->getType(), $message);
        } else {
            $this->Flash->info($message);
            $this->redirect(['action' => 'index']);
        }
    }

    public function updateJSON()
    {
        $results = $this->Servers->updateJSON();
        return $this->RestResponse->viewData($results, $this->response->getType());
    }

    public function createSync()
    {
        if ($this->isSiteAdmin()) {
            throw new MethodNotAllowedException('Site admin accounts cannot be used to create server sync configurations.');
        }
        $baseurl = Configure::read('MISP.external_baseurl');
        if (empty($baseurl)) {
            $baseurl = Configure::read('MISP.baseurl');
            if (empty($baseurl)) {
                $baseurl = Router::url('/', true);
            }
        }
        $host_org_id = Configure::read('MISP.host_org_id');
        if (empty($host_org_id)) {
            throw new MethodNotAllowedException(__('Cannot create sync config - no host org ID configured for the instance.'));
        }
        $OrganisationsTable = $this->fetchTable('Organisations');
        $host_org = $OrganisationsTable->find(
            'all',
            [
                'conditions' => ['Organisation.id' => $host_org_id],
                'recursive' => -1,
                'fields' => ['name', 'uuid']
            ]
        )->first();
        if (empty($host_org)) {
            throw new MethodNotAllowedException(__('Configured host org not found. Please make sure that the setting is current on the instance.'));
        }
        if (Configure::read('Security.advanced_authkeys')) {
            $AuthKeysTable = $this->fetchTable('AuthKeys');
            $authkey = $AuthKeysTable->createnewkey($this->ACL->getUser()->id, null, __('Auto generated sync key - %s', date('Y-m-d H:i:s')));
        } else {
            $UsersTable = $this->fetchTable('Users');
            $authkey = $UsersTable->find(
                'column',
                [
                    'conditions' => ['User.id' => $this->ACL->getUser()->id],
                    'recursive' => -1,
                    'fields' => ['User.authkey']
                ]
            );
            $authkey = $authkey[0];
        }
        $server = [
            'Server' => [
                'url' => $baseurl,
                'uuid' => Configure::read('MISP.uuid'),
                'authkey' => h($authkey),
                'Organisation' => [
                    'name' => $host_org['Organisation']['name'],
                    'uuid' => $host_org['Organisation']['uuid'],
                ]
            ]
        ];
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($server, $this->response->getType());
        } else {
            $this->set('server', $server);
        }
    }

    public function import()
    {
        if ($this->request->is('post')) {
            $server = $this->request->getData();
            if (isset($server['Server'])) {
                $server = $server['Server'];
            }
            if (isset($server['json'])) {
                $server = json_decode($server['json'], true)['Server'];
            }
            $OrganisationsTable = $this->fetchTable('Organisations');
            $org_id = $OrganisationsTable->captureOrg($server['Organisation'], $this->ACL->getUser());
            $toSave = [
                'push' => 0,
                'pull' => 0,
                'caching_enabled' => 0,
                'json' => '[]',
                'push_rules' => [],
                'pull_rules' => [],
                'self_signed' => 0,
                'org_id' => $this->ACL->getUser()->org_id,
                'remote_org_id' => $org_id,
                'name' => empty($server['name']) ? $server['url'] : $server['name'],
                'url' => $server['url'],
                'uuid' => $server['uuid'],
                'authkey' => $server['authkey']
            ];
            $this->Servers->create();
            $result = $this->Servers->save($toSave);
            if ($result) {
                if ($this->ParamHandler->isRest()) {
                    $server = $this->Servers->get($this->Servers->id);
                    return $this->RestResponse->viewData($server, $this->response->getType());
                } else {
                    $this->Flash->success(__('The server has been saved'));
                    $this->redirect(['action' => 'index', $this->Servers->id]);
                }
            } else {
                if ($this->ParamHandler->isRest()) {
                    return $this->RestResponse->saveFailResponse('Servers', 'addFromJson', false, $this->Servers->validationErrors, $this->response->getType());
                } else {
                    $this->Flash->error(__('Could not save the server. Error: %s', json_encode($this->Servers->validationErrors)));
                    $this->redirect(['action' => 'index']);
                }
            }
        }
    }

    public function resetRemoteAuthKey($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint expects POST requests.'));
        }
        $result = $this->Servers->resetRemoteAuthkey($id);
        if ($result !== true) {
            if (!$this->ParamHandler->isRest()) {
                $this->Flash->error($result);
                $this->redirect(['action' => 'index']);
            } else {
                $message = __('Could not update API key.');
                return $this->RestResponse->saveFailResponse('Servers', 'resetRemoteAuthKey', $id, $message, $this->response->getType());
            }
        } else {
            $message = __('API key updated.');
            if (!$this->ParamHandler->isRest()) {
                $this->Flash->success($message);
                $this->redirect(['action' => 'index']);
            } else {
                return $this->RestResponse->saveSuccessResponse('Servers', 'resetRemoteAuthKey', $message, $this->response->getType());
            }
        }
    }

    public function changePriority($id = false, $direction = 'down')
    {
        $this->Servers->id = $id;
        if (!$this->Servers->exists()) {
            throw new InvalidArgumentException(__('ID has to be a valid server connection'));
        }
        if ($direction !== 'up' && $direction !== 'down') {
            throw new InvalidArgumentException(__('Invalid direction. Valid options: ', 'up', 'down'));
        }
        $success = $this->Servers->reprioritise($id, $direction);
        if ($success) {
            $message = __('Priority changed.');
            return $this->RestResponse->saveSuccessResponse('Servers', 'changePriority', $message, $this->response->getType());
        } else {
            $message = __('Priority could not be changed.');
            return $this->RestResponse->saveFailResponse('Servers', 'changePriority', $id, $message, $this->response->getType());
        }
    }

    public function releaseUpdateLock()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint expects POST requests.'));
        }
        $this->Servers->changeLockState(false);
        $this->Servers->resetUpdateFailNumber();
        $this->redirect(['action' => 'updateProgress']);
    }

    public function dbSchemaDiagnostic()
    {
        $dbSchemaDiagnostics = $this->Servers->dbSchemaDiagnostic();
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($dbSchemaDiagnostics, $this->response->getType());
        } else {
            $this->set('checkedTableColumn', $dbSchemaDiagnostics['checked_table_column']);
            $this->set('dbSchemaDiagnostics', $dbSchemaDiagnostics['diagnostic']);
            $this->set('dbIndexDiagnostics', $dbSchemaDiagnostics['diagnostic_index']);
            $this->set('expectedDbVersion', $dbSchemaDiagnostics['expected_db_version']);
            $this->set('actualDbVersion', $dbSchemaDiagnostics['actual_db_version']);
            $this->set('error', $dbSchemaDiagnostics['error']);
            $this->set('remainingLockTime', $dbSchemaDiagnostics['remaining_lock_time']);
            $this->set('updateFailNumberReached', $dbSchemaDiagnostics['update_fail_number_reached']);
            $this->set('updateLocked', $dbSchemaDiagnostics['update_locked']);
            $this->set('dataSource', $dbSchemaDiagnostics['dataSource']);
            $this->set('columnPerTable', $dbSchemaDiagnostics['columnPerTable']);
            $this->set('indexes', $dbSchemaDiagnostics['indexes']);
            $this->render('/Elements/healthElements/db_schema_diagnostic');
        }
    }

    public function dbConfiguration()
    {
        $dbConfiguration = $this->Servers->dbConfiguration();
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($dbConfiguration, $this->response->getType());
        } else {
            $this->set('dbConfiguration', $dbConfiguration);
            $this->render('/Elements/healthElements/db_config_diagnostic');
        }
    }

    public function cspReport()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This action expects a POST request.');
        }

        $report = JsonTool::decode((string)$this->request->getBody());
        if (!isset($report['csp-report'])) {
            throw new RuntimeException("Invalid report");
        }

        $message = 'CSP reported violation';
        $remoteIp = $this->_remoteIp();
        if ($remoteIp) {
            $message .= ' from IP ' . $remoteIp;
        }
        $report = JsonTool::encode($report['csp-report'], true);
        if (strlen($report) > 1024 * 1024) { // limit report to 1 kB
            $report = substr($report, 0, 1024 * 1024) . '...';
        }
        $this->log("$message: $report");

        return new Response(['status' => 204]);
    }

    /**
     * List all tags for the rule picker.
     *
     * @return array
     */
    private function __getTags()
    {
        $TagsTable = $this->fetchTable('Tags');
        $list = $TagsTable->find(
            'list',
            [
                'recursive' => -1,
                'order' => ['LOWER(TRIM(Tag.name))' => 'ASC'],
                'fields' => ['name'],
            ]
        );
        $allTags = [];
        foreach ($list as $id => $name) {
            $allTags[] = ['id' => $id, 'name' => trim($name)];
        }
        return $allTags;
    }

    public function removeOrphanedCorrelations()
    {
        $count = $this->Servers->removeOrphanedCorrelations();
        $message = __('%s orphaned correlation removed', $count);
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($message, $this->response->getType());
        } else {
            $this->Flash->success($message);
            $this->redirect(['action' => 'serverSettings', 'diagnostics']);
        }
    }

    public function queryAvailableSyncFilteringRules($serverID)
    {
        if (!$this->ParamHandler->isRest()) {
            throw new MethodNotAllowedException(__('This method can only be access via REST'));
        }
        $server = $this->Servers->get($serverID);
        if (!$server) {
            throw new NotFoundException(__('Invalid server'));
        }
        $syncFilteringRules = $this->Servers->queryAvailableSyncFilteringRules($server);
        return $this->RestResponse->viewData($syncFilteringRules);
    }

    public function getAvailableSyncFilteringRules()
    {
        if (!$this->ParamHandler->isRest()) {
            throw new MethodNotAllowedException(__('This method can only be access via REST'));
        }
        $syncFilteringRules = $this->Servers->getAvailableSyncFilteringRules($this->ACL->getUser());
        return $this->RestResponse->viewData($syncFilteringRules);
    }

    public function pruneDuplicateUUIDs()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $AttributesTable = $this->fetchTable('Attributes');
        $duplicates = $AttributesTable->find(
            'all',
            [
                'fields' => ['Attribute.uuid', 'count(*) as occurance'],
                'recursive' => -1,
                'group' => ['Attribute.uuid HAVING COUNT(*) > 1'],
            ]
        );
        $counter = 0;
        foreach ($duplicates as $duplicate) {
            $attributes = $AttributesTable->find(
                'all',
                [
                    'recursive' => -1,
                    'conditions' => ['uuid' => $duplicate['Attribute']['uuid']]
                ]
            );
            foreach ($attributes as $k => $attribute) {
                if ($k > 0) {
                    $AttributesTable->delete($attribute['Attribute']['id']);
                    $counter++;
                }
            }
        }
        $this->Servers->updateDatabase('makeAttributeUUIDsUnique');
        $this->Flash->success('Done. Deleted ' . $counter . ' duplicate attribute(s).');
        $this->redirect(['controller' => 'pages', 'action' => 'display', 'administration']);
    }

    public function removeDuplicateEvents()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $EventsTable = $this->fetchTable('Events');
        $duplicates = $EventsTable->find(
            'all',
            [
                'fields' => ['Event.uuid', 'count(*) as occurance'],
                'recursive' => -1,
                'group' => ['Event.uuid HAVING COUNT(*) > 1'],
            ]
        );
        $counter = 0;

        // load this so we can remove the blocklist item that will be created, this is the one case when we do not want it.
        if (Configure::read('MISP.enableEventBlocklisting') !== false) {
            $EventsTableBlocklist = $this->fetchTable('EventBlocklist');
        }

        foreach ($duplicates as $duplicate) {
            $events = $EventsTable->find(
                'all',
                [
                    'recursive' => -1,
                    'conditions' => ['uuid' => $duplicate['Event']['uuid']]
                ]
            );
            foreach ($events as $k => $event) {
                if ($k > 0) {
                    $uuid = $event['Event']['uuid'];
                    $EventsTable->delete($event['Event']['id']);
                    $counter++;
                    // remove the blocklist entry that we just created with the event deletion, if the feature is enabled
                    // We do not want to block the UUID, since we just deleted a copy
                    if (Configure::read('MISP.enableEventBlocklisting') !== false) {
                        $EventsTableBlocklist->deleteAll(['EventBlocklist.event_uuid' => $uuid]);
                    }
                }
            }
        }
        $this->Servers->updateDatabase('makeEventUUIDsUnique');
        $this->Flash->success('Done. Removed ' . $counter . ' duplicate events.');
        $this->redirect(['controller' => 'pages', 'action' => 'display', 'administration']);
    }

    public function upgrade2324()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        if (!Configure::read('BackgroundJobs.enabled')) {
            $this->Servers->upgrade2324($this->ACL->getUser()->id);
            $this->Flash->success('Done. For more details check the audit logs.');
            $this->redirect(['controller' => 'pages', 'action' => 'display', 'administration']);
        } else {

            /** @var JobsTable $JobsTable */
            $JobsTable = $this->fetchTable('Jobs');
            $jobId = $JobsTable->createJob(
                $this->ACL->getUser(),
                Job::WORKER_DEFAULT,
                'upgrade_24',
                'Old database',
                __('Job created.')
            );

            $this->Servers->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'jobUpgrade24',
                    $jobId,
                    $this->ACL->getUser()->id,
                ],
                true,
                $jobId
            );

            $this->Flash->success(__('Job queued. You can view the progress if you navigate to the active jobs view (administration -> jobs).'));
            $this->redirect(['controller' => 'pages', 'action' => 'display', 'administration']);
        }
    }

    public function cleanModelCaches()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        $this->Servers->cleanCacheFiles();
        $this->Flash->success('Caches cleared.');
        $this->redirect(['controller' => 'servers', 'action' => 'serverSettings', 'diagnostics']);
    }

    public function updateDatabase($command)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        if (is_numeric($command)) {
            $command = intval($command);
        }
        $this->Servers->updateDatabase($command);
        $this->Flash->success('Done.');
        $this->redirect(['controller' => 'pages', 'action' => 'display', 'administration']);
    }

    public function ipUser($input = false)
    {
        $params = $this->harvestParameters(['ip']);
        if (!empty($params['ip'])) {
            $input = $params['ip'];
        }
        $redis = RedisTool::init();
        if (!is_array($input)) {
            $input = [$input];
        }
        $users = [];
        foreach ($input as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                continue;
            }
            $user_id = $redis->get('misp:ip_user:' . $ip);
            if (empty($user_id)) {
                continue;
            }
            $UsersTable = $this->fetchTable('Users');
            $user = $UsersTable->find(
                'all',
                [
                    'recursive' => -1,
                    'conditions' => ['User.id' => $user_id],
                    'contain' => ['Organisation.name']
                ]
            )->first();
            if (empty($user)) {
                throw new NotFoundException(__('User not found (perhaps it has been removed?).'));
            }
            $users[$ip] = [
                'id' => $user['User']['id'],
                'email' => $user['User']['email'],
            ];
        }
        return $this->RestResponse->viewData($users, $this->response->getType());
    }

    /**
     * @deprecated
     * @return void
     */
    public function rest()
    {
        $this->redirect(['controller' => 'api', 'action' => 'rest']);
    }
}
