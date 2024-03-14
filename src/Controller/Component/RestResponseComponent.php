<?php

namespace App\Controller\Component;

use App\Model\Entity\Distribution;
use Cake\Controller\Component;
use Cake\Core\Configure;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Utility\Inflector;
use Cake\Utility\Xml;

class RestResponseComponent extends Component
{
    use LocatorAwareTrait;

    public $components = ['ACL', 'APIRearrange'];

    public $headers = [];

    private $__convertActionToMessage = [
        'SharingGroup' => [
            'addOrg' => 'add Organisation to',
            'removeOrg' => 'remove Organisation from',
            'addServer' => 'add Server to',
            'removeServer' => 'remove Server from'
        ]
    ];

    private $___setup = false;

    private $__descriptions = [
        'Attribute' => [
            'add' => [
                'description' => "POST a MISP Attribute JSON to this API to create an Attribute.",
                'mandatory' => ['value', 'type'],
                'optional' => ['category', 'to_ids', 'uuid', 'distribution', 'sharing_group_id', 'timestamp', 'comment', 'data', 'encrypt', 'first_seen', 'last_seen'],
                'params' => ['event_id']
            ],
            'edit' => [
                'description' => "POST a MISP Attribute JSON to this API to update an Attribute. If the timestamp is set, it has to be newer than the existing Attribute.",
                'mandatory' => [],
                'optional' => ['value', 'type', 'category', 'to_ids', 'uuid', 'distribution', 'sharing_group_id', 'timestamp', 'comment', 'date', 'encrypt', 'first_seen', 'last_seen'],
                'params' => ['attribute_id']
            ],
            'deleteSelected' => [
                'description' => "POST a list of attribute IDs in JSON format to this API to delete the given attributes. This API also expects an event ID passed via the URL or via the event_id key. The id key also takes 'all' as a parameter for a wildcard search to mass delete attributes. If you want the function to also hard-delete already soft-deleted attributes, pass the allow_hard_delete key.",
                'mandatory' => ['id'],
                'optional' => ['event_id', 'allow_hard_delete'],
                'params' => ['event_id']
            ],
            'restSearch' => [
                'description' => "Search MISP using a list of filter parameters and return the data in the selected format. The search is available on an event and an attribute level, just select the scope via the URL (/events/restSearch vs /attributes/restSearch). Besides the parameters listed, other, format specific ones can be passed along (for example: requested_attributes and includeContext for the CSV export). This API allows pagination via the page and limit parameters.",
                'mandatory' => ['returnFormat'],
                'optional' => ['page', 'limit', 'value', 'type', 'category', 'org', 'tags', 'date', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'attribute_timestamp', 'enforceWarninglist', 'to_ids', 'deleted', 'includeEventUuid', 'includeEventTags', 'event_timestamp', 'threat_level_id', 'eventinfo', 'includeProposals', 'includeDecayScore', 'includeFullModel', 'decayingModel', 'excludeDecayed', 'score', 'first_seen', 'last_seen'],
                'params' => []
            ]
        ],
        'Community' => [
            'requestAccess' => [
                'description' => "POST a request object describing yourself and your organisation to request access to the desired community.",
                'mandatory' => [],
                'optional' => ['org_name', 'org_uuid', 'sync', 'org_description', 'email', 'message', 'anonymise', 'gpgkey', 'mock'],
                'params' => ['uuid']
            ]
        ],
        'Event' => [
            'add' => [
                'description' => "POST a MISP Event JSON to this API to create an Event. Contained objects can also be included (such as attributes, objects, tags, etc).",
                'mandatory' => ['info'],
                'optional' => ['threat_level_id', 'analysis', 'distribution', 'sharing_group_id', 'uuid', 'published', 'timestamp', 'date', 'Attribute', 'Object', 'Shadow_Attribute', 'EventTag'],
                'params' => []
            ],
            'edit' => [
                'description' => "POST a MISP Event JSON to this API to update an Event. Contained objects can also be included (such as attributes, objects, tags, etc). If the timestamp is set, it has to be newer than the existing Attribute.",
                'mandatory' => [],
                'optional' => ['info', 'threat_level_id', 'analysis', 'distribution', 'sharing_group_id', 'uuid', 'published', 'timestamp', 'date', 'Attribute', 'Object', 'Shadow_Attribute', 'EventTag'],
                'params' => ['event_id']
            ],
            'index' => [
                'description' => 'POST a JSON filter object to this API to get the meta-data about matching events.',
                'optional' => ['all', 'attribute', 'published', 'eventid', 'datefrom', 'dateuntil', 'org', 'eventinfo', 'tag', 'tags', 'distribution', 'sharinggroup', 'analysis', 'threatlevel', 'email', 'hasproposal', 'timestamp', 'publishtimestamp', 'publish_timestamp', 'minimal']
            ],
            'restSearch' => [
                'description' => "Search MISP using a list of filter parameters and return the data in the selected format. The search is available on an event and an attribute level, just select the scope via the URL (/events/restSearch vs /attributes/restSearch). Besides the parameters listed, other, format specific ones can be passed along (for example: requested_attributes and includeContext for the CSV export). This API allows pagination via the page and limit parameters.",
                'mandatory' => ['returnFormat'],
                'optional' => ['page', 'limit', 'value', 'type', 'category', 'org', 'tag', 'tags', 'searchall', 'date', 'last', 'eventid', 'withAttachments', 'metadata', 'uuid', 'published', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'sgReferenceOnly', 'eventinfo', 'excludeLocalTags', 'threat_level_id'],
                'params' => []
            ]
        ],
        'EventGraph' => [
            'add' => [
                'description' => "POST a network in JSON format to this API to to keep an history of it",
                'mandatory' => ['event_id', 'network_json'],
                'optional' => ['network_name']
            ]
        ],
        'Feed' => [
            'add' => [
                'description' => "POST a MISP Feed descriptor JSON to this API to add a Feed.",
                'mandatory' => ['source_format', 'url', 'name', 'input_source', 'provider'],
                'optional' => ['enabled', 'caching_enabled', 'lookup_visible', 'delete_local_file', 'headers', 'fixed_event', 'target_event', 'settings', 'publish', 'override_ids', 'delta_merge', 'distribution', 'sharing_group_id', 'tag_id', 'pull_rules', 'rules', 'event_id'],
                'params' => []
            ],
            'edit' => [
                'description' => "POST a MISP Feed descriptor JSON to this API to edit a Feed.",
                'mandatory' => [],
                'optional' => ['source_format', 'url', 'name', 'enabled', 'caching_enabled', 'lookup_visible', 'provider', 'input_source', 'delete_local_file', 'headers', 'fixed_event', 'target_event', 'settings', 'publish', 'override_ids', 'delta_merge', 'distribution', 'sharing_group_id', 'tag_id', 'pull_rules', 'rules', 'event_id'],
                'params' => ['feed_id']
            ],
            'previewIndex' => [
                'description' => 'Sending a GET request to this endpoint will show the parsed feed in JSON format.',
                'mandatory' => [],
                'optional' => [],
                'params' => ['feed_id'],
                'http_method' => 'GET'
            ]
        ],
        'Log' => [
            'admin_index' => [
                'description' => "POST a filter object to receive a JSON with the log entries matching the query. A simple get request will return the entire DB. You can use the filter parameters as url parameters with a GET request such as: https://path.to.my.misp/admin/logs/page:1/limit:200 - to run substring queries simply append/prepend/encapsulate the search term with %. All restSearch rules apply.",
                "optional" => ['id', 'title', 'created', 'model', 'model_id', 'action', 'user_id', 'change', 'email', 'org', 'description', 'ip']
            ],
            'event_index' => [
                'description' => "Simply run a get request on this endpoint to get the relevant log entries for a given event. This functionality is open to any user having access to a given event."
            ]
        ],
        'Organisation' => [
            'admin_add' => [
                'description' => "POST an Organisation object in JSON format to this API to create a new organsiation.",
                'mandatory' => ['name'],
                'optional' => ['description', 'type', 'nationality', 'sector', 'uuid', 'contacts', 'local']
            ],
            'admin_edit' => [
                'description' => "POST an Organisation object in JSON format to this API to create a new organsiation.",
                'mandatory' => ['name'],
                'optional' => ['description', 'type', 'nationality', 'sector', 'uuid', 'contacts', 'local']
            ]
        ],
        'Role' => [
            'admin_add' => [
                'description' => "POST a Role object in JSON format to this API to create a new role. 'permission' sets the data access permission (0 => read only, 1 => add/edit own, 2 => add/edit org, 3 => publish)",
                'mandatory' => ['name'],
                'optional' => [
                    'perm_delegate',
                    'perm_sync',
                    'perm_admin',
                    'perm_audit',
                    'perm_auth',
                    'perm_site_admin',
                    'perm_regexp_access',
                    'perm_tagger',
                    'perm_template',
                    'perm_sharing_group',
                    'perm_tag_editor',
                    'default_role',
                    'perm_sighting',
                    'permission'
                ]
            ],
            'admin_edit' => [
                'description' => "POST a Role object in JSON format to this API to edit a role. 'permission' sets the data access permission (0 => read only, 1 => add/edit own, 2 => add/edit org, 3 => publish)",
                'mandatory' => ['name'],
                'optional' => [
                    'perm_delegate',
                    'perm_sync',
                    'perm_admin',
                    'perm_audit',
                    'perm_auth',
                    'perm_site_admin',
                    'perm_regexp_access',
                    'perm_tagger',
                    'perm_template',
                    'perm_sharing_group',
                    'perm_tag_editor',
                    'default_role',
                    'perm_sighting',
                    'permission'
                ]
            ]
        ],
        'Server' => [
            'add' => [
                'description' => "POST an Server object in JSON format to this API to add a server.",
                'mandatory' => ['url', 'name', 'remote_org_id', 'authkey'],
                'optional' => ['push', 'pull', 'push_sightings', 'push_rules', 'pull_rules', 'submitted_cert', 'submitted_client_cert', 'json']
            ],
            'edit' => [
                'description' => "POST an Server object in JSON format to this API to edit a server.",
                'optional' => ['url', 'name', 'authkey', 'json', 'push', 'pull', 'push_sightings', 'push_rules', 'pull_rules', 'submitted_cert', 'submitted_client_cert', 'remote_org_id']
            ],
            'serverSettings' => [
                'description' => "Send a GET request to this endpoint to get a full diagnostic along with all currently set settings of the current instance. This will also include the worker status"
            ]
        ],
        'Sighting' => [
            'add' => [
                'description' => "POST a simplified sighting object in JSON format to this API to add a or a list of sightings. Pass either value(s) or attribute IDs (can be uuids) to identify the target sightings.",
                'mandatory' => ['OR' => ['values', 'id']],
                'optional' => ['type', 'source', 'timestamp', 'date', 'time']
            ],
            'restSearch' => [
                'description' => "Search MISP sightings using a list of filter parameters and return the data in the JSON format. The search is available on an event, attribute or instance level, just select the scope via the URL (/sighting/restSearch/event vs /sighting/restSearch/attribute vs /sighting/restSearch/). id MUST be provided if context is set.",
                'mandatory' => ['returnFormat'],
                'optional' => ['id', 'type', 'from', 'to', 'last', 'org_id', 'source', 'includeAttribute', 'includeEvent'],
                'params' => ['context']
            ],
        ],
        'SharingGroup' => [
            'add' => [
                'description' => "POST a Sharing Group object in JSON format to this API to add a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.",
                'mandatory' => ['name', 'releasability'],
                'optional' => ['description', 'uuid', 'organisation_uuid', 'active', 'created', 'modified', 'roaming', 'Server' => ['url', 'name', 'all_orgs'], 'Organisation' => ['uuid', 'name', 'extend']]
            ],
            'edit' => [
                'description' => "POST a Sharing Group object in JSON format to this API to edit a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.",
                'mandatory' => [],
                'optional' => ['name', 'releasability', 'description', 'uuid', 'organisation_uuid', 'active', 'created', 'modified', 'roaming', 'SharingGroupServer' => ['url', 'name', 'all_orgs'], 'SharingGroupOrg' => ['uuid', 'name', 'extend']]
            ]
        ],
        'Tag' => [
            'add' => [
                'description' => "POST a Tag object in JSON format to this API to create a new tag.",
                'mandatory' => ['name'],
                'optional' => ['colour', 'exportable', 'hide_tag', 'org_id', 'user_id']
            ],
            'edit' => [
                'description' => "POST or PUT a Tag object in JSON format to this API to create a edit an existing tag.",
                'optional' => ['name', 'colour', 'exportable', 'hide_tag', 'org_id', 'user_id'],
                'params' => ['tag_id']
            ],
            'removeTag' => [
                'description' => "POST a request object in JSON format to this API to create detach a tag from an event. #FIXME Function does not exists",
                'mandatory' => ['event', 'tag'],
                'params' => ['tag_id']
            ],
            'attachTagToObject' => [
                'description' => "Attach a Tag to an object, refenced by an UUID. Tag can either be a tag id or a tag name.",
                'mandatory' => ['uuid', 'tag'],
            ]
        ],
        'User' => [
            'admin_add' => [
                'description' => "POST a User object in JSON format to this API to create a new user.",
                'mandatory' => ['email', 'org_id', 'role_id'],
                'optional' => ['password', 'external_auth_required', 'external_auth_key', 'enable_password', 'nids_sid', 'server_id', 'gpgkey', 'certif_public', 'autoalert', 'contactalert', 'disabled', 'change_pw', 'termsaccepted', 'newsread']
            ],
            'admin_edit' => [
                'description' => "POST a User object in JSON format to this API to edit a user.",
                'optional' => ['email', 'org_id', 'role_id', 'password', 'external_auth_required', 'external_auth_key', 'enable_password', 'nids_sid', 'server_id', 'gpgkey', 'certif_public', 'autoalert', 'contactalert', 'disabled', 'change_pw', 'termsaccepted', 'newsread']
            ],
            'admin_quickEmail' => [
                'description' => "POST a body and a subject in a JSON to send an e-mail through MISP to the user ID given in the URL",
                'mandatory' => ['subject', 'body']
            ],
            'change_pw' => [
                'description' => "POST a password via a JSON object containing the password key to reset the given user\'s password.",
                'mandatory' => ['password']
            ],
            'statistics' => [
                'description' => 'Simply GET the url endpoint to view the API output of the statistics API. Additional statistics are available via the following tab-options similar to the UI: data, orgs, users, tags, attributehistogram, sightings, attackMatrix',
                'params' => ['tab'],
                'http_method' => 'GET'
            ]
        ],
        'UserSetting' => [
            'setSetting' => [
                'description' => "POST a User setting object in JSON format to this API to create a new setting or update the equivalent existing setting. Admins/site admins can specify a user ID besides their own.",
                'mandatory' => ['setting', 'value'],
                'optional' => ['user_id']
            ],
            'delete' => [
                'description' => "POST or DELETE to this API to delete an existing setting.",
                'params' => ['id']
            ]
        ],
        'Warninglist' => [
            'checkValue' => [
                'description' => "POST a JSON list with value(s) to check against the warninglists to get a JSON dictionary as a response with any hits, if there are any (with the key being the passed value triggering a warning).",
                'mandatory' => ['[]']
            ],
            'toggleEnable' => [
                'description' => "POST a json object with a single or a list of warninglist IDsIDs, or alternatively a (list of) substring(s) that match the names of warninglist(s) to toggle whether they're enabled or disabled. Specify the optional enabled boolean flag if you would like to enforce the outcome state. Not setting this flag will just toggle the current state.", 'mandatory' => ['id'],
                'optional' => ['id', 'name', 'enabled']
            ]
        ]
    ];

    private $__scopedFieldsConstraint = [];

    public function initialize(array $config): void
    {
        $this->__configureFieldConstraints();
        $this->Controller = $this->getController();
    }

    public function getAllApisFieldsConstraint($user)
    {
        $this->__setup();
        $result = [];
        foreach ($this->__scopedFieldsConstraint as $controller => $actions) {
            $controller = Inflector::tableize($controller);
            foreach ($actions as $action => $data) {
                if ($this->ACL->checkAccess($user, $controller, $action, true) === true) {
                    $admin_routing = '';
                    if (substr($action, 0, 6) === 'admin_') {
                        $action = substr($action, 6);
                        $admin_routing = 'admin/';
                    }
                    $url = '/' . $admin_routing . $controller . '/' . $action;
                    $result[$url] = $data;
                }
            }
        }
        return $result;
    }

    public function getAllApis($user)
    {
        $this->__setup();
        $result = [];
        foreach ($this->__descriptions as $controller => $actions) {
            $controller = Inflector::tableize($controller);
            foreach ($actions as $action => $data) {
                if ($this->ACL->checkAccess($user, $controller, $action, true) === true) {
                    $admin_routing = '';
                    if (substr($action, 0, 6) === 'admin_') {
                        $action = substr($action, 6);
                        $admin_routing = 'admin/';
                    }
                    $data['api_name'] = '[' . $controller . '] ' . $action;
                    $data['controller'] = $controller;
                    $data['action'] = $action;
                    $data['body'] = [];
                    $filter_types = ['mandatory', 'optional'];
                    foreach ($filter_types as $filter_type) {
                        if (!empty($data[$filter_type])) {
                            foreach ($data[$filter_type] as $filter_items) {
                                if (!is_array($filter_items)) {
                                    $filter_items = [$filter_items];
                                }
                                foreach ($filter_items as $filter) {
                                    if ($filter === lcfirst($filter)) {
                                        $data['body'][$filter] = $filter_type;
                                    } else {
                                        $data['body'][$filter] = [$filter_type];
                                    }
                                }
                            }
                        }
                    }
                    $data['body'] = json_encode($data['body'], JSON_PRETTY_PRINT);
                    $url = '/' . $admin_routing . $controller . '/' . $action;
                    $data['url'] = $url;
                    if (!empty($data['params'])) {
                        foreach ($data['params'] as $param) {
                            $data['url'] .= '/[' . $param . ']';
                        }
                    }
                    $result[$url] = $data;
                }
            }
        }
        return $result;
    }

    // use a relative path to check if the current api has a description
    public function getApiInfo($relative_path)
    {
        $this->__setup();
        $relative_path = trim($relative_path, '/');
        $relative_path = explode('/', $relative_path);
        $admin = false;
        if (count($relative_path) >= 2) {
            if ($relative_path[0] == 'admin') {
                if (count($relative_path) < 3) {
                    return '[]';
                }
                $admin = true;
                $relative_path = array_slice($relative_path, 1);
            }
            $relative_path[0] = Inflector::camelize(Inflector::singularize($relative_path[0]));
            if ($admin) {
                $relative_path[1] = 'admin_' . $relative_path[1];
            }
            if (isset($this->__descriptions[$relative_path[0]][$relative_path[1]])) {
                $temp = $this->__descriptions[$relative_path[0]][$relative_path[1]];
            } else {
                $temp = [];
            }
            if (empty($temp)) {
                return '[]';
            }
            return json_encode(['api_info' => $temp], JSON_PRETTY_PRINT);
        }
        return '[]';
    }

    public function saveFailResponse($controller, $action, $id, $validationErrors, $format = false)
    {
        $this->autoRender = false;
        $response = [];
        $action = $this->__dissectAdminRouting($action);
        $stringifiedAction = $action['action'];
        if (isset($this->__convertActionToMessage[$controller][$action['action']])) {
            $stringifiedAction = $this->__convertActionToMessage[$controller][$action['action']];
        }
        $response['saved'] = false;
        $response['name'] = 'Could not ' . $stringifiedAction . ' ' . Inflector::singularize($controller);
        $response['message'] = $response['name'];
        $response['url'] = $this->__generateURL($action, $controller, $id);
        $response['errors'] = $validationErrors;
        return $this->__sendResponse($response, 403, $format);
    }

    public function saveSuccessResponse($controller, $action, $id = false, $format = false, $message = false)
    {
        $action = $this->__dissectAdminRouting($action);
        if (!$message) {
            $message = Inflector::singularize($controller) . ' ' . $action['action'] . ((substr($action['action'], -1) == 'e') ? 'd' : 'ed');
        }
        $response['saved'] = true;
        $response['success'] = true;
        $response['name'] = $message;
        $response['message'] = $response['name'];
        $response['url'] = $this->__generateURL($action, $controller, $id);
        return $this->__sendResponse($response, 200, $format);
    }

    public function ajaxSuccessResponse($ObjectAlias, $action, $entity, $message, $additionalData = [])
    {
        $action = $this->__dissectAdminRouting($action);
        $entity = is_array($entity) ? $entity : $entity->toArray();
        $response = [
            'success' => true,
            'message' => $message,
            'data' => $entity,
            'url' =>  !empty($entity['id']) ? $this->__generateURL($action, $ObjectAlias, $entity['id']) : ''
        ];
        if (!empty($additionalData)) {
            $response['additionalData'] = $additionalData;
        }
        return $this->viewData($response);
    }

    public function ajaxFailResponse($ObjectAlias, $action, $entity, $message, $errors = [])
    {
        $action = $this->__dissectAdminRouting($action);
        $entity = is_array($entity) ? $entity : $entity->toArray();
        $response = [
            'success' => false,
            'message' => $message,
            'errors' => $errors,
            'url' =>  !empty($entity['id']) ? $this->__generateURL($action, $ObjectAlias, $entity['id']) : ''
        ];
        return $this->viewData($response);
    }

    private function __sendResponse($response, $code, $format = false, $raw = false, $download = false, $headers = [], $deprecationWarnings = [])
    {
        if (strtolower($format) === 'application/xml' || strtolower($format) === 'xml') {
            if (!$raw) {
                if (isset($response[0])) {
                    if (count(array_keys($response[0])) == 1) {
                        $key = array_keys($response[0])[0];
                        $rearrange = [];
                        foreach ($response as $k => $v) {
                            $rearrange[$key][] = $v[$key];
                        }
                        $response = $rearrange;
                    }
                }
                $response = ['response' => $response];
                $response = Xml::fromArray($response, ['format' => 'tags']);
                $response = $response->asXML();
            }
            $type = 'xml';
        } elseif (strtolower($format) == 'openioc') {
            $type = 'xml';
        } elseif (strtolower($format) == 'csv') {
            $type = 'csv';
        } else {
            if (empty($format)) {
                $type = 'json';
            } else {
                $type = $format;
            }
            if (!$raw) {
                if (is_string($response)) {
                    $response = ['message' => $response];
                }
                if (Configure::read('debug') > 1 && !empty($this->Controller->sql_dump)) {
                    $this->Log = $this->fetchTable('Logs');
                    if ($this->Controller->sql_dump === 2) {
                        $response = ['sql_dump' => $this->Log->getDataSource()->getLog(false, false)];
                    } else {
                        $response['sql_dump'] = $this->Log->getDataSource()->getLog(false, false);
                    }
                }
                $response = json_encode($response, JSON_PRETTY_PRINT);
            } else {
                if (Configure::read('debug') > 1 && !empty($this->Controller->sql_dump)) {
                    $this->Log = $this->fetchTable('Logs');
                    if ($this->Controller->sql_dump === 2) {
                        $response = json_encode(['sql_dump' => $this->Log->getDataSource()->getLog(false, false)]);
                    } else {
                        $response = substr_replace(
                            $response,
                            sprintf(', "sql_dump": %s}', json_encode($this->Log->getDataSource()->getLog(false, false))),
                            -2
                        );
                    }
                }
            }
        }
        $cakeResponse = new \Cake\Http\Response();
        $cakeResponse = $cakeResponse->withType($type);
        $cakeResponse = $cakeResponse->withStatus($code);
        $cakeResponse = $cakeResponse->withStringBody($response);

        if (Configure::read('Security.allow_cors')) {
            $headers["Access-Control-Allow-Headers"] =  "Origin, Content-Type, Authorization, Accept";
            $headers["Access-Control-Allow-Methods"] = "*";
            $headers["Access-Control-Allow-Origin"] = explode(',', Configure::read('Security.cors_origins'));
            $headers["Access-Control-Expose-Headers"] = ["X-Result-Count"];
        }
        if (!empty($this->headers)) {
            foreach ($this->headers as $key => $value) {
                $cakeResponse = $cakeResponse->withHeader($key, $value);
            }
        }
        if (!empty($headers)) {
            foreach ($headers as $key => $value) {
                $cakeResponse = $cakeResponse->withHeader($key, $value);
            }
        }
        if (!empty($deprecationWarnings)) {
            $cakeResponse = $cakeResponse->withHeader('X-Deprecation-Warning', $deprecationWarnings);
        }
        if ($download) {
            $cakeResponse = $cakeResponse->withDownload($download);
        }

        return $cakeResponse;
    }

    private function __generateURL($action, $controller, $id)
    {
        $controller = Inflector::underscore(Inflector::pluralize($controller));
        return ($action['admin'] ? '/admin' : '') . '/' . $controller . '/' . $action['action'] . ($id ? '/' . $id : '');
    }

    private function __dissectAdminRouting($action)
    {
        $admin = false;
        if (strlen($action) > 6 && substr($action, 0, 6) == 'admin_') {
            $action = substr($action, 6);
            $admin = true;
        }
        return ['action' => $action, 'admin' => $admin];
    }

    public function viewData($data, $format = false, $errors = false, $raw = false, $download = false, $headers = [], $wrapResponse = false)
    {
        if (!empty($errors)) {
            $data['errors'] = $errors;
        }
        if (!$raw && is_object($data)) {
            $data = $this->APIRearrange->rearrangeForAPI($data, $wrapResponse);
        }
        return $this->__sendResponse($data, 200, $format, $raw, $download, $headers);
    }

    public function sendFile($path, $format = false, $download = false, $name = 'download')
    {
        $cakeResponse = new \Cake\Http\Response();
        $cakeResponse = $cakeResponse->withStatus(200);
        $cakeResponse = $cakeResponse->withType($format);
        $cakeResponse = $cakeResponse->withDownload($path, ['download' => true, 'name' => $name]);
        return $cakeResponse;
    }

    public function throwException($code, $message, $url = '', $format = false, $raw = false, $headers = [])
    {
        $message = [
            'name' => $message,
            'message' => $message,
            'url' => $url
        ];
        return $this->__sendResponse($message, $code, $format, $raw, false, $headers);
    }

    public function setHeader($header, $value)
    {
        $this->headers[$header] = $value;
    }

    public function describe($controller, $action, $id = false, $format = false)
    {
        $this->__setup();
        $actionArray = $this->__dissectAdminRouting($action);
        $response['name'] = $this->__generateURL($actionArray, $controller, false) . ' API description';
        $response['description'] = isset($this->__descriptions[Inflector::singularize($controller)][$action]['description']) ? $this->__descriptions[Inflector::singularize($controller)][$action]['description'] : 'This API is not accessible via GET requests.';
        if (isset($this->__descriptions[Inflector::singularize($controller)][$action]['mandatory'])) {
            $response['mandatory_fields'] = $this->__descriptions[Inflector::singularize($controller)][$action]['mandatory'];
        }
        if (isset($this->__descriptions[Inflector::singularize($controller)][$action]['optional'])) {
            $response['optional_fields'] = $this->__descriptions[Inflector::singularize($controller)][$action]['optional'];
        }
        $params = '';
        if (!empty($this->__descriptions[Inflector::singularize($controller)][$action]['params'])) {
            foreach ($this->__descriptions[Inflector::singularize($controller)][$action]['params'] as $k => $param) {
                $params .= ($k > 0 ? '/' : '') . '[' . $param . ']';
            }
        }
        $response['url'] = $this->__generateURL($actionArray, $controller, $params);
        return $this->__sendResponse($response, 200, $format);
    }

    private function __setup()
    {
        if (!$this->__setup) {
            $scopes = ['Event', 'Attribute', 'Sighting'];
            foreach ($scopes as $scope) {
                $this->{$scope} = $this->fetchTable($scope);
                $this->__descriptions[$scope]['restSearch'] = [
                    'description' => $this->__descriptions[$scope]['restSearch']['description'],
                    'returnFormat' => array_keys($this->{$scope}->validFormats),
                    'mandatory' => $this->__descriptions[$scope]['restSearch']['mandatory'],
                    'optional' => $this->__descriptions[$scope]['restSearch']['optional'],
                    'params' => $this->__descriptions[$scope]['restSearch']['params']
                ];
            }
            $this->__setupFieldsConstraint();
        }
        return true;
    }

    private $__fieldConstraint = [];

    // default value and input for API field
    private function __configureFieldConstraints()
    {
        $this->__fieldsConstraint = [
            'action' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal'],
                'values' => ['action1'],
                'help' => __('The action that the user performed')
            ],
            'active' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Is the sharing group selectable (active) when chosing distribution')
            ],
            'all' => [
                'input' => 'text',
                'type' => 'string',
                'help' => __('Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields')
            ],
            'all_orgs' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('All organisations contained on the instance will be part of the sharing group')
            ],
            'allow_hard_delete' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('hard-delete already soft-deleted attributes')
            ],
            'analysis' => [
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'values' => [0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed'],
                'help' => __('Maturity of the event')
            ],
            'anonymise' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'operators' => ['equal'],
                'help' => __('Anonymise the information regarding the server on which the request was issued')
            ],
            'attribute' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Filter on attribute value')
            ],
            'authkey' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The authorisation key found on the external server')
            ],
            'autoalert' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The user receive alerts when events are published')
            ],
            'body' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The email\'s body')
            ],
            'caching_enabled' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The feed is cached')
            ],
            'category' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'values' => ['categ1'],
            ],
            'certif_public' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('A valid x509 certificate ')
            ],
            'changed' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The text contained in the changed field')
            ],
            'change_pw' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The user will be prompted the change the password')
            ],
            'colour' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('A valid hexadecimal colour `#ffffff`')
            ],
            'comment' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal']
            ],
            'contacts' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Contact details for the organisation')
            ],
            'contactalert' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The user receive alerts from `contact reporter` requests')
            ],
            'created' => [
                'type' => 'date',
                'validation' => ['format' => 'YYYY-MM-DD'],
                'plugin' => 'datepicker',
                'plugin_config' => [
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ],
            ],
            'data' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Base64 encoded file contents')
            ],
            'date' => [
                'type' => 'date',
                'validation' => ['format' => 'YYYY-MM-DD'],
                'plugin' => 'datepicker',
                'plugin_config' => [
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ],
                'help' => __('The user set date field on the event level. If you are using restSearch, you can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.)')
            ],
            'datefrom' => [
                'type' => 'date',
                'validation' => ['format' => 'YYYY-MM-DD'],
                'plugin' => 'datepicker',
                'plugin_config' => [
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ],
            ],
            'dateuntil' => [
                'type' => 'date',
                'validation' => ['format' => 'YYYY-MM-DD'],
                'plugin' => 'datepicker',
                'plugin_config' => [
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ],
            ],
            'decayingModel' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'unique' => true,
                'help' => 'Specify the decaying model from which the decaying score should be calculated'
            ],
            'default_role' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The role is a default role (selected by default)')
            ],
            'delete_local_file' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Remove file after ingestion')
            ],
            'deleted' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Include deleted elements')
            ],
            'delta_merge' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Merge attributes (only add new attribute, remove revoked attributes)')
            ],
            'description' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
            ],
            'disabled' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Disable the user account')
            ],
            'distribution' => [
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'values' => [0 => 'dist1'],
            ],
            'email' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('Filter on user email')
            ],
            'enable_password' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Set the password manually')
            ],
            'enabled' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'encrypt' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('When uploading malicious samples, set this flag to tell MISP to encrpyt the sample and extract the file hashes. This will create a MISP object with the appropriate attributes.')
            ],
            //'enforceWarningList' => array(
            //    'input' => 'radio',
            //    'type' => 'integer',
            //    'values' => array(1 => 'True', 0 => 'False' )
            //),
            'enforceWarninglist' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Should the warning list be enforced. Adds `blocked` field for matching attributes')
            ],
            'event_id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1]
            ],
            'event_timestamp' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1],
                'help' => __('The timestamp at which the event was last modified')
            ],
            'attribute_timestamp' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1],
                'help' => __('The timestamp at which the attribute was last modified')
            ],
            'eventid' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1]
            ],
            'eventinfo' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('Quick event description')
            ],
            'exportable' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The tag is exported when synchronising with other instances')
            ],
            'excludeDecayed' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => 'Should the decayed elements by excluded'
            ],
            'excludeLocalTags' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Exclude local tags from the export')
            ],
            'extend' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The organisation have write access to this sharing group (they can add/remove other organisation)')
            ],
            'external_auth_required' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('An external authorisation is required for this user')
            ],
            'external_auth_key' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('A valid external auth key')
            ],
            'first_seen' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => 'A valid ISO 8601 datetime format, up to milli-seconds. i.e.: 2019-06-13T15:56:56.856074+02:00'
            ],
            'fixed_event' => [
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal'],
                'values' => [0 => 'New Event Each Pull', 1 => 'Fixed Event'],
                'help' => __('target_event option might be considered')
            ],
            'from' => [
                'type' => 'date',
                'validation' => ['format' => 'YYYY-MM-DD'],
                'plugin' => 'datepicker',
                'plugin_config' => [
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ],
                'help' => __('The date from which the event was published')
            ],
            'gpgkey' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('A valid GPG key')
            ],
            'hasproposal' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The event contains proposals')
            ],
            'headers' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Headers to be passed with the requests. All separated by `\n`')
            ],
            'hide_tag' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The tag is hidden (not selectable)')
            ],
            'id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1]
            ],
            'includeAttribute' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Include matching attributes in the response')
            ],
            'includeDecayScore' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => 'Include all enabled decaying score'
            ],
            'includeEvent' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Include matching events in the response')
            ],
            'includeEventUuid' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Include matching eventUuids in the response')
            ],
            'includeEventTags' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Include tags of matching events in the response')
            ],
            'includeFullModel' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => 'Include all model information of matching events in the response'
            ],
            'includeProposals' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Include proposals of matching events in the response')
            ],
            'info' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('Quick event description')
            ],
            'input_source' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal'],
                'values' => ['network' => 'Network', 'local' => 'Local'],
                'help' => __('Specify whether the source (url field) is a directory (local) or an geniun url (network)')
            ],
            'ip' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The IP of a login attempt')
            ],
            'json' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('JSON containing ID, UUID and name')
            ],
            'last' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m)')
            ],
            'last_seen' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => 'A valid ISO 8601 datetime format, up to milli-seconds. i.e.: 2019-06-13T15:56:56.856074+02:00'
            ],
            'limit' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
                'help' => __('Limit on the pagination')
            ],
            'local' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('If the organisation should have access to this instance, make sure that the Local organisation setting is checked. If you would only like to add a known external organisation for inclusion in sharing groups, uncheck the Local organisation setting.')
            ],
            'lookup_visible' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The lookup will not be visible in the feed correlation')
            ],
            'message' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('Message to be included')
            ],
            'metadata' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Will only return the metadata of the given query scope, contained data is omitted.')
            ],
            'minimal' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Will only return  id, timestamp, published and uuid')
            ],
            'mock' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'operators' => ['equal'],
                'help' => __('Mock the query')
            ],
            'model' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal'],
                'values' => ['Attribute', 'Event', 'EventBlacklist', 'EventTag', 'MispObject', 'Organisation', 'Post', 'Regexp', 'Role', 'Server', 'ShadowAttribute', 'SharingGroup', 'Tag', 'Task', 'Taxonomy', 'Template', 'Thread', 'User', 'Whitelist'],
            ],
            'model_id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
            ],
            'modified' => [
                'type' => 'date',
                'validation' => ['format' => 'YYYY-MM-DD'],
                'plugin' => 'datepicker',
                'plugin_config' => [
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ],
                'help' => __('The last time the sharing group was modified')
            ],
            'name' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
            ],
            'nationality' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal'],
                'values' => ['nat1'],
            ],
            'newsread' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
                'help' => __('The news are read')
            ],
            'nids_sid' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
                'help' => __('The unique Signature Identification')
            ],
            'org' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('Can be either the ORG_ID or the ORG_NAME')
            ],
            'org_description' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('Describe the organisation')
            ],
            'org_name' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('Organisation identifier (name)')
            ],
            'org_id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
            ],
            'org_uuid' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Globally used uuid of an organisation')
            ],
            'organisation_uuid' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Globally used uuid of an organisation')
            ],
            'override_ids' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The IDS flags will be set to off for this feed')
            ],
            'page' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 1, 'step' => 1],
                'help' => __('Page number for the pagination')
            ],
            'password' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The hardcoded password')
            ],
            'perm_admin' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_audit' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_auth' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_delegate' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_regexp_access' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_sharing_group' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_sighting' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_site_admin' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_sync' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_tag_editor' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_tagger' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'perm_template' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'permission' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal'],
                'values' => [0 => 'Read Only', 1 => 'Manage Own Events', 2 => 'Manage Organisation Events', 3 => 'Manage and Publish Organisation Events'],
            ],
            'provider' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('The name of the feed provider')
            ],
            'publish' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The event will be published')
            ],
            'publish_timestamp' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1]
            ],
            'published' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'publishtimestamp' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1]
            ],
            'pull' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Allow the download of events and their attribute from the server')
            ],
            'push' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Allow the upload of events and their attribute to the server')
            ],
            'push_sightings' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Allow the upload of sightings to the server')
            ],
            'releasability' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Concise summary for who this sharing group is releasable to')
            ],
            'remote_org_id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
            ],
            'returnFormat' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal'],
                'values' => ['json', 'openioc', 'xml', 'suricata', 'snort', 'text', 'rpz', 'csv', 'cache', 'stix', 'stix2'],
            ],
            'roaming' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Pass the event to any connected instance where the sync connection is tied to an organisation contained in the SG organisation list')
            ],
            'role_id' => [
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => [0 => 'role1'],
            ],
            'score' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1, 'max' => 100],
                'help' => 'An alias to override on-the-fly the threshold of the decaying model'
            ],
            'searchall' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields')
            ],
            'sector' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The sector of the organisation')
            ],
            'server_id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
            ],
            'sgReferenceOnly' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('Will only return the sharing group ID')
            ],
            'sharing_group_id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1]
            ],
            'sharinggroup' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1],
                'help' => __('Sharing group ID')
            ],
            'source' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The source of the Sighting (e.g. honeypot_1)')
            ],
            'source_format' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'values' => ['misp' => 'MISP Feed', 'freetext' => 'Freetext Parsed Feed', 'csv' => 'CSV Parsed Feed']
            ],
            'subject' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The email\'s subject')
            ],
            'submitted_cert' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Base64 encoded certificate')
            ],
            'submitted_client_cert' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Base64 encoded certificate')
            ],
            'sync' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'operators' => ['equal']
            ],
            'tag' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
            ],
            'tag_id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
                'help' => __('A tad ID to attach to created events')
            ],
            'tags' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'unique' => false,
            ],
            'target_event' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
                'help' => __('The provided ID will be reused as an existing event')
            ],
            'termsaccepted' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],
            'threat_level_id' => [
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'values' => [1 => 'High', 2 => 'Medium', 3 => 'Low', 4 => 'Undefined']
            ],
            'threatlevel' => [
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'values' => [1 => 'High', 2 => 'Medium', 3 => 'Low', 4 => 'Undefined']
            ],
            'time' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Time of the sighting with the form `h:i:s`')
            ],
            'timestamp' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'validation' => ['min' => 0, 'step' => 1]
            ],
            'title' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('The title of the log')
            ],
            'to' => [
                'type' => 'date',
                'validation' => ['format' => 'YYYY-MM-DD'],
                'plugin' => 'datepicker',
                'plugin_config' => [
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ],
                'help' => __('The date to which the event was published')
            ],
            'to_ids' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False'],
                'help' => __('The state of the `to_ids` flag')
            ],
            'type' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
                'help' => __('The type of the attribute')
            ],
            'url' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal'],
            ],
            'user_id' => [
                'input' => 'number',
                'type' => 'integer',
                'operators' => ['equal'],
                'validation' => ['min' => 0, 'step' => 1],
            ],
            'uuid' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal']
            ],
            'value' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal', 'not_equal']
            ],
            'values' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'unique' => false,
                'help' => __('Placeholder containing values to sight')
            ],
            'withAttachments' => [
                'input' => 'radio',
                'type' => 'integer',
                'values' => [1 => 'True', 0 => 'False']
            ],

            // Not supported yet
            '[]' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported (warninglist->checkvalues) expect an array')
            ],
            'event' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported (removeTag)')
            ],
            'push_rules' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],
            'pull_rules' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],
            'rules' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],

            'settings' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],
            'network_name' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],
            'network_json' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],
            'Attribute' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],
            'Object' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],
            'EventTag' => [
                'input' => 'select',
                'type' => 'string',
                'operators' => ['equal'],
            ],
            'Shadow_Attribute' => [
                'input' => 'text',
                'type' => 'string',
                'operators' => ['equal'],
                'help' => __('Not supported')
            ],
        ];
    }

    // create dictionnary mapping between fields constraints and scope->action
    private function __setupFieldsConstraint()
    {
        foreach ($this->__descriptions as $scope => $desc) {
            foreach ($desc as $action => $params) {
                $fieldsConstraint = [];
                foreach ($params as $paramType => $field) {
                    if ($paramType == 'optional' || $paramType == 'mandatory') {
                        $fields = array_values($field);
                        if (!empty($fields)) {
                            foreach ($fields as $field) {
                                if (is_array($field)) {
                                    foreach ($field as $sf) {
                                        $fieldsConstraint[$sf] = $this->__fieldsConstraint[$sf];
                                        $label = $scope . '.' . $sf;
                                        $fieldsConstraint[$sf]['id'] = $label;
                                        $fieldsConstraint[$sf]['label'] = $label;
                                    }
                                } else {
                                    if (!empty($this->__fieldsConstraint[$field])) {
                                        $fieldsConstraint[$field] = $this->__fieldsConstraint[$field];
                                        $label = $scope . '.' . $field;
                                        $fieldsConstraint[$field]['id'] = $label;
                                        $fieldsConstraint[$field]['label'] = $label;
                                    }
                                }

                                // add dynamic data and overwrite name collisions
                                switch ($field) {
                                    case "returnFormat":
                                        $this->__overwriteReturnFormat($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    case "type":
                                        $this->__overwriteType($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    case "category":
                                        $this->__overwriteCategory($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    case "decayingModel":
                                        $this->__overwriteDecayingModel($scope, $fieldsConstraint[$field]);
                                        break;
                                    case "distribution":
                                        $this->__overwriteDistribution($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    case "tag":
                                    case "tags":
                                    case "EventTag":
                                        $this->__overwriteTags($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    case "nationality":
                                        $this->__overwriteNationality($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    case "action":
                                        $this->__overwriteAction($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    case "role_id":
                                        $this->__overwriteRoleId($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    case "first_seen":
                                    case "last_seen":
                                        $this->__overwriteSeen($scope, $action, $fieldsConstraint[$field]);
                                        break;
                                    default:
                                        break;
                                }
                            }
                        }
                    }
                }
                $this->__scopedFieldsConstraint[$scope][$action] = $fieldsConstraint;
            }
        }
    }

    // Fetch the correct values based on the scope, then overwrite default value
    private function __overwriteReturnFormat($scope, $action, &$field)
    {
        switch ($scope) {
            case "Attribute":
                $field['values'] = array_keys($this->fetchTable($scope)->validFormats);
                break;
            case "Event":
                $field['values'] = array_keys($this->fetchTable($scope)->validFormats);
                break;
        }
    }
    private function __overwriteType($scope, $action, &$field)
    {
        $field['input'] = 'select';
        switch ($scope) {
            case "Attribute":
                $field['values'] = array_keys($this->fetchTable($scope)->typeDefinitions);
                break;
            case "Event":
                $field['values'] = array_keys($this->fetchTable("Attribute")->typeDefinitions);
                break;
            case "Sighting":
                $field['values'] = $this->fetchTable($scope)->type;
                break;
            default:
                $field['input'] = 'text';
                break;
        }
    }

    private function __overwriteCategory($scope, $action, &$field)
    {
        $field['values'] = array_keys($this->fetchTable("Attribute")->categoryDefinitions);
    }
    private function __overwriteDistribution($scope, $action, &$field)
    {
        $field['values'] = [];
        foreach (Distribution::ALL as $d => $text) {
            $field['values'][] = ['label' => $text, 'value' => $d];
        }
    }
    private function __overwriteDecayingModel($scope, &$field)
    {
        $this->{$scope} = $this->fetchTable("DecayingModel");
        $models = $this->{$scope}->find(
            'list',
            [
                'recursive' => -1,
                'fields' => ['name']
            ]
        );
        $field['values'] = [];
        foreach ($models as $i => $model_name) {
            $field['values'][] = ['label' => h($model_name), 'value' => $i];
        }
    }
    private function __overwriteTags($scope, $action, &$field)
    {
        $this->{$scope} = $this->fetchTable("Tag");
        $tags = $this->{$scope}->find(
            'list',
            [
                'recursive' => -1,
                'fields' => ['name']
            ]
        );
        foreach ($tags as $i => $tag) {
            $tagname = htmlspecialchars($tag);
            $tags[$tagname] = $tagname;
            unset($tags[$i]);
        }
        $field['values'] = $tags;
    }
    private function __overwriteNationality($scope, $action, &$field)
    {
        $field['values'] = $this->fetchTable("Organisation")->countries;
    }
    private function __overwriteAction($scope, $action, &$field)
    {
        $field['values'] = array_keys($this->fetchTable("Log")->actionDefinitions);
    }
    private function __overwriteRoleId($scope, $action, &$field)
    {
        $this->{$scope} = $this->fetchTable("Role");
        $roles = $this->{$scope}->find(
            'list',
            [
                'recursive' => -1,
                'fields' => ['name']
            ]
        );
        $field['values'] = $roles;
    }
    private function __overwriteSeen($scope, $action, &$field)
    {
        if ($action == 'restSearch') {
            $field['help'] = __('Seen within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m)');
        }
    }

    /**
     * Detect if request comes from automatic tool (like other MISP instance or PyMISP) or AJAX
     * @return bool
     */
    public function isAutomaticTool()
    {
        if ($this->Controller->getRequest()->is('ajax')) {
            return true;
        }
        $userAgent = $this->Controller->getRequest()->getHeader('User-Agent');
        return count($userAgent) && (substr($userAgent[0], 0, 6) === 'PyMISP' || substr($userAgent[0], 0, 4) === 'MISP');
    }
}
