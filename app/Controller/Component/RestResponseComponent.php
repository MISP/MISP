<?php

/**
 * @property ACLComponent $ACL
 */
class RestResponseComponent extends Component
{
    public $components = array('ACL');

    public $headers = array();

    private $__convertActionToMessage = array(
        'SharingGroup' => array(
            'addOrg' => 'add Organisation to',
            'removeOrg' => 'remove Organisation from',
            'addServer' => 'add Server to',
            'removeServer' => 'remove Server from'
        )
    );

    private $__setup = false;

    /** @var array */
    private $__fieldsConstraint;

    private $__descriptions = array(
        'Attribute' => array(
            'add' => array(
                'description' => "POST a MISP Attribute JSON to this API to create an Attribute.",
                'mandatory' => array('value', 'type'),
                'optional' => array('category', 'to_ids', 'uuid', 'distribution', 'sharing_group_id', 'timestamp', 'comment', 'data', 'encrypt', 'first_seen', 'last_seen'),
                'params' => array('event_id')
            ),
            'edit' => array(
                'description' => "POST a MISP Attribute JSON to this API to update an Attribute. If the timestamp is set, it has to be newer than the existing Attribute.",
                'mandatory' => array(),
                'optional' => array('value', 'type', 'category', 'to_ids', 'uuid', 'distribution', 'sharing_group_id', 'timestamp', 'comment', 'date', 'encrypt', 'first_seen', 'last_seen'),
                'params' => array('attribute_id')
            ),
            'deleteSelected' => array(
                'description' => "POST a list of attribute IDs in JSON format to this API to delete the given attributes. This API also expects an event ID passed via the URL or via the event_id key. The id key also takes 'all' as a parameter for a wildcard search to mass delete attributes. If you want the function to also hard-delete already soft-deleted attributes, pass the allow_hard_delete key.",
                'mandatory' => array('id'),
                'optional' => array('event_id', 'allow_hard_delete'),
                'params' => array('event_id')
            ),
            'restSearch' => array(
                'description' => "Search MISP using a list of filter parameters and return the data in the selected format. The search is available on an event and an attribute level, just select the scope via the URL (/events/restSearch vs /attributes/restSearch). Besides the parameters listed, other, format specific ones can be passed along (for example: requested_attributes and includeContext for the CSV export). This API allows pagination via the page and limit parameters.",
                'mandatory' => array('returnFormat'),
                'optional' => array('page', 'limit', 'value' , 'type', 'category', 'org', 'tags', 'date', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'attribute_timestamp', 'enforceWarninglist', 'to_ids', 'deleted', 'includeEventUuid', 'includeEventTags', 'event_timestamp', 'threat_level_id', 'eventinfo', 'includeProposals', 'includeDecayScore', 'includeFullModel', 'decayingModel', 'excludeDecayed', 'score', 'first_seen', 'last_seen'),
                'params' => array()
            ),
            'addTag' => array(
                'description' => "Add a tag or a tag collection to an attribute.",
                'mandatory' => array('attribute', 'tag')
            ),
            'removeTag' => array(
                'description' => "Remove a tag from an attribute.",
                'mandatory' => array('attribute', 'tag')
            ),
        ),
        'Community' => array(
            'requestAccess' => array(
                'description' => "POST a request object describing yourself and your organisation to request access to the desired community.",
                'mandatory' => array(),
                'optional' => array('org_name', 'org_uuid', 'sync', 'org_description', 'email', 'message', 'anonymise', 'gpgkey', 'mock'),
                'params' => array('uuid')
            )
        ),
        'Event' => array(
            'add' => array(
                'description' => "POST a MISP Event JSON to this API to create an Event. Contained objects can also be included (such as attributes, objects, tags, etc).",
                'mandatory' => array('info'),
                'optional' => array('threat_level_id', 'analysis', 'distribution', 'sharing_group_id', 'uuid', 'published', 'timestamp', 'date', 'Attribute', 'Object', 'Shadow_Attribute', 'EventTag'),
                'params' => array()
            ),
            'edit' => array(
                'description' => "POST a MISP Event JSON to this API to update an Event. Contained objects can also be included (such as attributes, objects, tags, etc). If the timestamp is set, it has to be newer than the existing Attribute.",
                'mandatory' => array(),
                'optional' => array('info', 'threat_level_id', 'analysis', 'distribution', 'sharing_group_id', 'uuid', 'published', 'timestamp', 'date', 'Attribute', 'Object', 'Shadow_Attribute', 'EventTag'),
                'params' => array('event_id')
            ),
            'index' => array(
                'description' => 'POST a JSON filter object to this API to get the meta-data about matching events.',
                'optional' => array('all', 'attribute', 'published', 'eventid', 'datefrom', 'dateuntil', 'org', 'eventinfo', 'tag', 'tags', 'distribution', 'sharinggroup', 'analysis', 'threatlevel', 'email', 'hasproposal', 'timestamp', 'publishtimestamp', 'publish_timestamp', 'minimal')
            ),
            'restSearch' => array(
                'description' => "Search MISP using a list of filter parameters and return the data in the selected format. The search is available on an event and an attribute level, just select the scope via the URL (/events/restSearch vs /attributes/restSearch). Besides the parameters listed, other, format specific ones can be passed along (for example: requested_attributes and includeContext for the CSV export). This API allows pagination via the page and limit parameters.",
                'mandatory' => array('returnFormat'),
                'optional' => array('page', 'limit', 'value', 'type', 'category', 'org', 'tag', 'tags', 'searchall', 'date', 'last', 'eventid', 'withAttachments', 'metadata', 'uuid', 'published', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'sgReferenceOnly', 'eventinfo', 'excludeLocalTags', 'threat_level_id'),
                'params' => array()
            ),
            'addTag' => array(
                'description' => "Add a tag or a tag collection to an event.",
                'mandatory' => array('event', 'tag')
            ),
            'removeTag' => array(
                'description' => "Remove a tag from an event.",
                'mandatory' => array('event', 'tag')
            ),
        ),
        'EventGraph' => array(
            'add' => array(
                'description' => "POST a network in JSON format to this API to to keep an history of it",
                'mandatory' => array('event_id', 'network_json'),
                'optional' => array('network_name')
            )
        ),
        'EventReport' => array(
            'add' => array(
                'description' => "POST a report in JSON format to create a report for the provided event",
                'mandatory' => array('name'),
                'optional' => array('distribution', 'content')
            ),
            'edit' => array(
                'description' => "POST a report in JSON format to update the report",
                'mandatory' => array(),
                'optional' => array('name', 'distribution', 'content')
            )
        ),
        'Feed' => array(
            'add' => array(
                'description' => "POST a MISP Feed descriptor JSON to this API to add a Feed.",
                'mandatory' => array('source_format', 'url', 'name', 'input_source', 'provider'),
                'optional' => array('enabled', 'caching_enabled', 'lookup_visible', 'delete_local_file', 'headers', 'fixed_event', 'target_event', 'settings', 'publish', 'override_ids', 'delta_merge', 'distribution', 'sharing_group_id', 'tag_id', 'pull_rules', 'rules', 'event_id'),
                'params' => array()
            ),
            'edit' => array(
                'description' => "POST a MISP Feed descriptor JSON to this API to edit a Feed.",
                'mandatory' => array(),
                'optional' => array('source_format', 'url', 'name', 'enabled', 'caching_enabled', 'lookup_visible', 'provider', 'input_source', 'delete_local_file', 'headers', 'fixed_event', 'target_event', 'settings', 'publish', 'override_ids', 'delta_merge', 'distribution', 'sharing_group_id', 'tag_id', 'pull_rules', 'rules', 'event_id'),
                'params' => array('feed_id')
            ),
            'previewIndex' => array(
                'description' => 'Sending a GET request to this endpoint will show the parsed feed in JSON format.',
                'mandatory' => array(),
                'optional' => array(),
                'params' => array('feed_id'),
                'http_method' => 'GET'
            )
        ),
        'GalaxyCluster' => array(
            'add' => array(
                'description' => "POST a MISP GalaxyCluster JSON to this API to create a GalaxyCluster. Contained objects can also be included (such as relations, elements, tags, etc).",
                'mandatory' => array('value', 'description'),
                'optional' => array('distribution', 'sharing_group_id', 'uuid', 'version', 'extends_uuid', 'extends_version', 'elements', 'GalaxyClusterRelation'),
                'params' => array('galaxy_id')
            ),
            'edit' => array(
                'description' => "POST a MISP GalaxyCluster JSON to this API to edit a GalaxyCluster",
                'mandatory' => array('value', 'description'),
                'optional' => array('distribution', 'sharing_group_id', 'uuid', 'version', 'extends_uuid', 'extends_version', 'elements'),
                'params' => array('cluster_id')
            ),
            'restSearch' => array(
                'description' => "Search MISP using a list of filter parameters and return the data in the selected format. This API allows pagination via the page and limit parameters.",
                'optional' => array('page', 'limit', 'id', 'uuid', 'galaxy_id', 'galaxy_uuid', 'version', 'distribution', 'org_id', 'orgc_id', 'tag_name', 'custom', 'minimal', 'published', 'value', 'extends_uuid'),
                'params' => array()
            ),
        ),
        'GalaxyClusterRelation' => array(
            'add' => array(
                'description' => "POST a MISP GalaxyClusterRelation JSON to this API to create a GalaxyCluster relation. Contained objects can also be included (such as tags).",
                'mandatory' => array('galaxy_cluster_uuid', 'referenced_galaxy_cluster_uuid', 'referenced_galaxy_cluster_type'),
                'optional' => array('distribution', 'sharing_group_id', 'tags'),
                'params' => array()
            ),
            'edit' => array(
                'description' => "POST a MISP GalaxyClusterRelation JSON to this API to edit a GalaxyCluster relation. Contained objects can also be included (such as tags).",
                'mandatory' => array('galaxy_cluster_uuid', 'referenced_galaxy_cluster_uuid', 'referenced_galaxy_cluster_type'),
                'optional' => array('distribution', 'sharing_group_id', 'tags'),
                'params' => array('relation_id')
            ),
        ),
        'Log' => array(
            'admin_index' => array(
                'description' => "POST a filter object to receive a JSON with the log entries matching the query. A simple get request will return the entire DB. You can use the filter parameters as url parameters with a GET request such as: https://path.to.my.misp/admin/logs/page:1/limit:200 - to run substring queries simply append/prepend/encapsulate the search term with %. All restSearch rules apply.",
                "optional" => array('id', 'title', 'created', 'model', 'model_id', 'action', 'user_id', 'change', 'email', 'org', 'description', 'ip')
            ),
            'event_index' => array(
                'description' => "Simply run a get request on this endpoint to get the relevant log entries for a given event. This functionality is open to any user having access to a given event."
            )
        ),
        'Organisation' => array(
            'admin_add' => array(
                'description' => "POST an Organisation object in JSON format to this API to create a new organsiation.",
                'mandatory' => array('name'),
                'optional' => array('description', 'type', 'nationality', 'sector', 'uuid', 'contacts', 'local')
            ),
            'admin_edit' => array(
                'description' => "POST an Organisation object in JSON format to this API to create a new organsiation.",
                'mandatory' => array('name'),
                'optional' => array('description', 'type', 'nationality', 'sector', 'uuid', 'contacts', 'local')
            )
        ),
        'Role' => array(
            'admin_add' => array(
                'description' => "POST a Role object in JSON format to this API to create a new role. 'permission' sets the data access permission (0 => read only, 1 => add/edit own, 2 => add/edit org, 3 => publish)",
                'mandatory' => array('name'),
                'optional' => array(
                    'perm_delegate',
                    'perm_sync',
                    'perm_admin',
                    'perm_audit',
                    'perm_auth',
                    'perm_site_admin',
                    'perm_regexp_access',
                    'perm_tagger',
                    'perm_galaxy_editor',
                    'perm_template',
                    'perm_sharing_group',
                    'perm_tag_editor',
                    'default_role',
                    'perm_sighting',
                    'permission'
                )
            ),
            'admin_edit' => array(
                'description' => "POST a Role object in JSON format to this API to edit a role. 'permission' sets the data access permission (0 => read only, 1 => add/edit own, 2 => add/edit org, 3 => publish)",
                'mandatory' => array('name'),
                'optional' => array(
                    'perm_delegate',
                    'perm_sync',
                    'perm_admin',
                    'perm_audit',
                    'perm_auth',
                    'perm_site_admin',
                    'perm_regexp_access',
                    'perm_tagger',
                    'perm_galaxy_editor',
                    'perm_template',
                    'perm_sharing_group',
                    'perm_tag_editor',
                    'default_role',
                    'perm_sighting',
                    'permission'
                )
            )
        ),
        'Server' => array(
            'add' => array(
                'description' => "POST an Server object in JSON format to this API to add a server.",
                'mandatory' => array('url', 'name', 'remote_org_id', 'authkey'),
                'optional' => array('push', 'pull', 'push_sightings', 'push_rules', 'pull_rules', 'submitted_cert', 'submitted_client_cert', 'json')
            ),
            'edit' => array(
                'description' => "POST an Server object in JSON format to this API to edit a server.",
                'optional' => array('url', 'name', 'authkey', 'json', 'push', 'pull', 'push_sightings', 'push_rules', 'pull_rules', 'submitted_cert', 'submitted_client_cert', 'remote_org_id')
            ),
            'serverSettings' => array(
                'description' => "Send a GET request to this endpoint to get a full diagnostic along with all currently set settings of the current instance. This will also include the worker status"
            )
        ),
        'Sighting' => array(
            'add' => array(
                'description' => "POST a simplified sighting object in JSON format to this API to add a or a list of sightings. Pass either value(s) or attribute IDs (can be uuids) to identify the target sightings.",
                'mandatory' => array('OR' => array('values', 'id')),
                'optional' => array('type', 'source', 'timestamp', 'date', 'time')
            ),
            'restSearch' => array(
                'description' => "Search MISP sightings using a list of filter parameters and return the data in the JSON format. The search is available on an event, attribute or instance level, just select the scope via the URL (/sighting/restSearch/event vs /sighting/restSearch/attribute vs /sighting/restSearch/). id or uuid MUST be provided if context is set.",
                'mandatory' => array('returnFormat'),
                'optional' => array('id', 'uuid', 'type', 'from', 'to', 'last', 'org_id', 'source', 'includeAttribute', 'includeEvent'),
                'params' => array('context')
            ),
        ),
        'SharingGroup' => array(
            'add' => array(
                'description' => "POST a Sharing Group object in JSON format to this API to add a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.",
                'mandatory' => array('name', 'releasability'),
                'optional' => array('description', 'uuid', 'organisation_uuid', 'active', 'created', 'modified', 'roaming', 'Server' => array('url', 'name', 'all_orgs'), 'Organisation' => array('uuid', 'name', 'extend'))
            ),
            'edit' => array(
                'description' => "POST a Sharing Group object in JSON format to this API to edit a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.",
                'mandatory' => array(),
                'optional' => array('name', 'releasability', 'description', 'uuid', 'organisation_uuid', 'active', 'created', 'modified', 'roaming', 'SharingGroupServer' => array('url', 'name', 'all_orgs'), 'SharingGroupOrg' => array('uuid', 'name', 'extend'))
            )
        ),
        'Tag' => array(
            'add' => array(
                'description' => "POST a Tag object in JSON format to this API to create a new tag.",
                'mandatory' => array('name'),
                'optional' => array('colour', 'exportable', 'hide_tag', 'org_id', 'user_id')
            ),
            'edit' => array(
                'description' => "POST or PUT a Tag object in JSON format to this API to create a edit an existing tag.",
                'optional' => array('name', 'colour', 'exportable', 'hide_tag', 'org_id', 'user_id'),
                'params' => array('tag_id')
            ),
            'removeTagFromObject' => array(
                'description' => "Untag an event or attribute. Tag can be the id or the name.",
                'mandatory' => array('uuid', 'tag')
            ),
            'attachTagToObject' => array(
                'description' => "Attach a Tag to an object, refenced by an UUID. Tag can either be a tag id or a tag name.",
                'mandatory' => array('uuid', 'tag'),
            ),
            'search' => array(
                'description' => "GET or POST the tags to search for as a raw string or as a list. The strict_tag_name_only parameter only returns tags matching exactly the tag name (thus, skipping synonyms and cluster's value)",
                'params' => array('tag_name', 'strict_tag_name_only')
            )
        ),
        'User' => array(
            'admin_add' => array(
                'description' => "POST a User object in JSON format to this API to create a new user.",
                'mandatory' => array('email', 'org_id', 'role_id'),
                'optional' => array('password', 'external_auth_required', 'external_auth_key', 'enable_password', 'nids_sid', 'server_id', 'gpgkey', 'certif_public', 'autoalert', 'contactalert', 'disabled', 'change_pw', 'termsaccepted', 'newsread')
            ),
            'admin_edit' => array(
                'description' => "POST a User object in JSON format to this API to edit a user.",
                'optional' => array('email', 'org_id', 'role_id', 'password', 'external_auth_required', 'external_auth_key', 'enable_password', 'nids_sid', 'server_id', 'gpgkey', 'certif_public', 'autoalert', 'contactalert', 'disabled', 'change_pw', 'termsaccepted', 'newsread')
            ),
            'admin_quickEmail' => array(
                'description' => "POST a body and a subject in a JSON to send an e-mail through MISP to the user ID given in the URL",
                'mandatory' => array('subject', 'body')
            ),
            'change_pw' => array(
                'description' => "POST a password via a JSON object containing the password key to reset the given user\'s password.",
                'mandatory' => array('password')
            ),
            'statistics' => array(
                'description' => 'Simply GET the url endpoint to view the API output of the statistics API. Additional statistics are available via the following tab-options similar to the UI: data, orgs, users, tags, attributehistogram, sightings, attackMatrix',
                'params' => array('tab'),
                'http_method' => 'GET'
            )
        ),
        'UserSetting' => array(
            'setSetting' => array(
                'description' => "POST a User setting object in JSON format to this API to create a new setting or update the equivalent existing setting. Admins/site admins can specify a user ID besides their own.",
                'mandatory' => array('setting', 'value'),
                'optional' => array('user_id')
            ),
            'delete' => array(
                'description' => "POST or DELETE to this API to delete an existing setting.",
                'params' => array('id')
            )
        ),
        'Warninglist' => array(
            'checkValue' => array(
                'description' => "POST a JSON list with value(s) to check against the warninglists to get a JSON dictionary as a response with any hits, if there are any (with the key being the passed value triggering a warning).",
                'mandatory' => array('[]')
            ),
            'toggleEnable' => array(
                'description' => "POST a json object with a single or a list of warninglist IDsIDs, or alternatively a (list of) substring(s) that match the names of warninglist(s) to toggle whether they're enabled or disabled. Specify the optional enabled boolean flag if you would like to enforce the outcome state. Not setting this flag will just toggle the current state.",'mandatory' => array('id'),
                'optional' => array('id', 'name', 'enabled')
            )
        )
    );

    private $__scopedFieldsConstraint = array();

    /** @var Controller */
    private $Controller;

    public function initialize(Controller $controller)
    {
        $this->Controller = $controller;
    }

    public function getAllApisFieldsConstraint($user)
    {
        $this->__setup();
        $result = array();
        foreach ($this->__scopedFieldsConstraint as $controller => $actions) {
            // EventGraph controller has different rule
            $controller = $controller === 'EventGraph' ? 'event_graph' : Inflector::tableize($controller);
            foreach ($actions as $action => $data) {
                if ($this->ACL->canUserAccess($user, $controller, $action)) {
                    $admin_routing = '';
                    if (substr($action, 0, 6) === 'admin_') {
                        $action = substr($action, 6);
                        $admin_routing = 'admin/';
                    }
                    $url = $this->baseurl . '/' . $admin_routing . $controller . '/' . $action;
                    $result[$url] = $data;
                }
            }
        }
        return $result;
    }

    public function getAllApis($user)
    {
        $this->__setup();
        $result = array();
        foreach ($this->__descriptions as $controller => $actions) {
            // EventGraph controller has different rule
            $controller = $controller === 'EventGraph' ? 'event_graph' : Inflector::tableize($controller);
            foreach ($actions as $action => $data) {
                if ($this->ACL->canUserAccess($user, $controller, $action)) {
                    $admin_routing = '';
                    if (substr($action, 0, 6) === 'admin_') {
                        $action = substr($action, 6);
                        $admin_routing = 'admin/';
                    }
                    $data['api_name'] = '[' . $controller . '] ' . $action;
                    $data['controller'] = $controller;
                    $data['action'] = $action;
                    $data['body'] = array();
                    $filter_types = array('mandatory', 'optional');
                    foreach ($filter_types as $filter_type) {
                        if (!empty($data[$filter_type])) {
                            foreach ($data[$filter_type] as $filter_items) {
                                if (!is_array($filter_items)) {
                                    $filter_items = array($filter_items);
                                }
                                foreach ($filter_items as $filter) {
                                    if ($filter === lcfirst($filter)) {
                                        $data['body'][$filter] = $filter_type;
                                    } else {
                                        $data['body'][$filter] = array($filter_type);
                                    }
                                }
                            }
                        }
                    }
                    $data['body'] = json_encode($data['body'], JSON_PRETTY_PRINT);
                    $url = $this->baseurl . '/' . $admin_routing . $controller . '/' . $action;
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

    public function getScopedApiInfo($user)
    {
        $api = $this->getAllApis($user);
        $scopedApi = [];
        foreach ($api as $apiEntry) {
            $scopeApi[$apiEntry['controller']][] = $apiEntry;
        }
        return $scopeApi;
    }

    /**
     * Use a relative path to check if the current api has a description
     * @param string $relative_path
     * @return array
     */
    public function getApiInfo($relative_path)
    {
        $this->__setup();
        $relative_path = trim($relative_path, '/');
        $relative_path = explode('/', $relative_path);
        $admin = false;
        if (count($relative_path) >= 2) {
            if ($relative_path[0] == 'admin') {
                if (count($relative_path) < 3) {
                    return [];
                }
                $admin = true;
                $relative_path = array_slice($relative_path, 1);
            }
            $relative_path[0] = Inflector::camelize(Inflector::singularize($relative_path[0]));
            if ($admin) {
                $relative_path[1] = 'admin_' . $relative_path[1];
            }
            if (isset($this->__descriptions[$relative_path[0]][$relative_path[1]])) {
                return $this->__descriptions[$relative_path[0]][$relative_path[1]];
            }
        }
        return [];
    }

    public function saveFailResponse($controller, $action, $id = false, $validationErrors, $format = false, $data = null)
    {
        $this->autoRender = false;
        $response = array();
        $action = $this->__dissectAdminRouting($action);
        $stringifiedAction = $action['action'];
        if (isset($this->__convertActionToMessage[$controller][$action['action']])) {
            $stringifiedAction = $this->__convertActionToMessage[$controller][$action['action']];
        }
        $response['saved'] = false;
        $response['name'] = 'Could not ' . $stringifiedAction . ' ' . Inflector::singularize($controller);
        $response['message'] = $response['name'];
        if (!is_null($data)) {
            $response['data'] = $data;
        }
        $response['url'] = $this->__generateURL($action, $controller, $id);
        $response['errors'] = $validationErrors;
        return $this->__sendResponse($response, 403, $format);
    }

    public function saveSuccessResponse($controller, $action, $id = false, $format = false, $message = false, $data = null)
    {
        $action = $this->__dissectAdminRouting($action);
        if (!$message) {
            $message = Inflector::singularize($controller) . ' ' . $action['action'] . ((substr($action['action'], -1) == 'e') ? 'd' : 'ed');
        }
        $response['saved'] = true;
        $response['success'] = true;
        $response['name'] = $message;
        $response['message'] = $response['name'];
        if (!is_null($data)) {
            $response['data'] = $data;
        }
        $response['url'] = $this->__generateURL($action, $controller, $id);
        return $this->__sendResponse($response, 200, $format);
    }

    /**
     * @param mixed $response
     * @param int $code
     * @param string|false $format
     * @param bool $raw
     * @param bool $download
     * @param array $headers
     * @return CakeResponse
     */
    private function __sendResponse($response, $code, $format = false, $raw = false, $download = false, $headers = array())
    {
        $format = strtolower($format);
        if ($format === 'application/xml' || $format === 'xml') {
            if (!$raw) {
                if (isset($response[0])) {
                    if (count(array_keys($response[0])) == 1) {
                        $key = array_keys($response[0])[0];
                        $rearrange = array();
                        foreach ($response as $k => $v) {
                            $rearrange[$key][] = $v[$key];
                        }
                        $response = $rearrange;
                    }
                }
                $response = array('response' => $response);
                $response = Xml::fromArray($response, array('format' => 'tags'));
                $response = $response->asXML();
            }
            $type = 'xml';
        } elseif ($format === 'openioc') {
            $type = 'xml';
        } elseif ($format === 'csv') {
            $type = 'csv';
        } else {
            if (empty($format)) {
                $type = 'json';
            } else {
                $type = $format;
            }
            $dumpSql = !empty($this->Controller->sql_dump) && Configure::read('debug') > 1;
            if (!$raw) {
                if (is_string($response)) {
                    $response = array('message' => $response);
                }
                if ($dumpSql) {
                    $this->Log = ClassRegistry::init('Log');
                    if ($this->Controller->sql_dump === 2) {
                        $response = array('sql_dump' => $this->Log->getDataSource()->getLog(false, false));
                    } else {
                        $response['sql_dump'] = $this->Log->getDataSource()->getLog(false, false);
                    }
                }
                // Do not pretty print response for automatic tools
                $flags = $this->isAutomaticTool() ? JSON_UNESCAPED_UNICODE : JSON_PRETTY_PRINT;
                $response = json_encode($response, $flags);
            } else {
                if ($dumpSql) {
                    $this->Log = ClassRegistry::init('Log');
                    if ($this->Controller->sql_dump === 2) {
                        $response = json_encode(array('sql_dump' => $this->Log->getDataSource()->getLog(false, false)));
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

        App::uses('TmpFileTool', 'Tools');
        if ($response instanceof TmpFileTool) {
            App::uses('CakeResponseTmp', 'Tools');
            $cakeResponse = new CakeResponseTmp(['status' => $code, 'type' => $type]);
            $cakeResponse->file($response);
        } else {
            $cakeResponse = new CakeResponse(array('body' => $response, 'status' => $code, 'type' => $type));
        }

        if (Configure::read('Security.allow_cors')) {
            $headers["Access-Control-Allow-Headers"] =  "Origin, Content-Type, Authorization, Accept";
            $headers["Access-Control-Allow-Methods"] = "*";
            $headers["Access-Control-Allow-Origin"] = explode(',', Configure::read('Security.cors_origins'));
            $headers["Access-Control-Expose-Headers"] = ["X-Result-Count"];
        }
        if (Configure::read('Security.disable_browser_cache')) {
            $cakeResponse->disableCache();
        }
        if (!empty($this->headers)) {
            $cakeResponse->header($this->headers);
        }
        if (!empty($headers)) {
            $cakeResponse->header($headers);
        }
        if (!empty($deprecationWarnings)) {
            $cakeResponse->header('X-Deprecation-Warning', $deprecationWarnings);
        }
        if ($download) {
            $cakeResponse->download($download);
        }
        return $cakeResponse;
    }

    /**
     * Detect if request comes from automatic tool (like other MISP instance or PyMISP) or AJAX
     * @return bool
     */
    public function isAutomaticTool()
    {
        if ($this->Controller->request->is('ajax')) {
            return true;
        }
        $userAgent = CakeRequest::header('User-Agent');
        return $userAgent && (substr($userAgent, 0, 6) === 'PyMISP' || substr($userAgent, 0, 4) === 'MISP');
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
        return array('action' => $action, 'admin' => $admin);
    }

    public function viewData($data, $format = false, $errors = false, $raw = false, $download = false, $headers = array())
    {
        if (!empty($errors)) {
            $data['errors'] = $errors;
        }
        return $this->__sendResponse($data, 200, $format, $raw, $download, $headers);
    }

    public function sendFile($path, $format = false, $download = false, $name = 'download')
    {
        $cakeResponse = new CakeResponse(array(
            'status' => 200,
            'type' => $format
        ));
        $cakeResponse->file($path, array('name' => $name, 'download' => true));
        return $cakeResponse;
    }

    public function throwException($code, $message, $url = '', $format = false, $raw = false, $headers = array())
    {
        $message = array(
            'name' => $message,
            'message' => $message,
            'url' => $url
        );
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
                $params .= ($k > 0 ? '/': '') . '[' . $param . ']';
            }
        }
        $response['url'] = $this->__generateURL($actionArray, $controller, $params);
        return $this->__sendResponse($response, 200, $format);
    }

    private function __setup()
    {
        if (!$this->__setup) {
            $scopes = array('Event', 'Attribute', 'Sighting');
            foreach ($scopes as $scope) {
                $this->{$scope} = ClassRegistry::init($scope);
                $this->__descriptions[$scope]['restSearch'] = array(
                    'description' => $this->__descriptions[$scope]['restSearch']['description'],
                    'returnFormat' => array_keys($this->{$scope}->validFormats),
                    'mandatory' => $this->__descriptions[$scope]['restSearch']['mandatory'],
                    'optional' => $this->__descriptions[$scope]['restSearch']['optional'],
                    'params' => $this->__descriptions[$scope]['restSearch']['params']
                );
            }
            $this->__configureFieldConstraints();
            $this->__setupFieldsConstraint();
            $this->__setup = true;
        }
        return true;
    }

    // default value and input for API field
    private function __configureFieldConstraints()
    {
        $this->__fieldsConstraint = array(
            'action' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal'),
                'values' => array('action1'),
                'help' => __('The action that the user performed')
            ),
            'active' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Is the sharing group selectable (active) when choosing distribution')
            ),
            'all' => array(
                'input' => 'text',
                'type' => 'string',
                'help' => __('Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields')
            ),
            'all_orgs' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('All organisations contained on the instance will be part of the sharing group')
            ),
            'allow_hard_delete' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('hard-delete already soft-deleted attributes')
            ),
            'analysis' => array(
                'input' => 'select',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'values' => array( 0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed'),
                'help' => __('Maturity of the event')
            ),
            'anonymise' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'operators' => array('equal'),
                'help' => __('Anonymise the information regarding the server on which the request was issued')
            ),
            'attribute' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Filter on attribute value')
            ),
            'authkey' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The authorisation key found on the external server')
            ),
            'autoalert' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The user receive alerts when events are published')
            ),
            'body' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The email\'s body')
            ),
            'caching_enabled' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The feed is cached')
            ),
            'category' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'values' => array('categ1'),
            ),
            'certif_public' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('A valid x509 certificate ')
            ),
            'change' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The text contained in the change field')
            ),
            'change_pw' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The user will be prompted the change the password')
            ),
            'colour' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('A valid hexadecimal colour `#ffffff`')
            ),
            'comment' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal')
            ),
            'contacts' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Contact details for the organisation')
            ),
            'contactalert' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The user receive alerts from `contact reporter` requests')
            ),
            'created' => array(
                'type' => 'date',
                'validation' => array( 'format' => 'YYYY-MM-DD' ),
                'plugin' => 'datepicker',
                'plugin_config' => array(
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ),
            ),
            'data' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Base64 encoded file contents')
            ),
            'date' => array(
                'type' => 'date',
                'validation' => array( 'format' => 'YYYY-MM-DD' ),
                'plugin' => 'datepicker',
                'plugin_config' => array(
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ),
                'help' => __('The user set date field on the event level. If you are using restSearch, you can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.)')
            ),
            'datefrom' => array(
                'type' => 'date',
                'validation' => array( 'format' => 'YYYY-MM-DD' ),
                'plugin' => 'datepicker',
                'plugin_config' => array(
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ),
            ),
            'dateuntil' => array(
                'type' => 'date',
                'validation' => array( 'format' => 'YYYY-MM-DD' ),
                'plugin' => 'datepicker',
                'plugin_config' => array(
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ),
            ),
            'decayingModel' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'unique' => true,
                'help' => 'Specify the decaying model from which the decaying score should be calculated'
            ),
            'default_role' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The role is a default role (selected by default)')
            ),
            'delete_local_file' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Remove file after ingestion')
            ),
            'deleted' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Include deleted elements')
            ),
            'delta_merge' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Merge attributes (only add new attribute, remove revoked attributes)')
            ),
            'description' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
            ),
            'disabled' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Disable the user account')
            ),
            'distribution' => array(
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'values' => array(0 => 'dist1'),
            ),
            'email' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('Filter on user email')
            ),
            'enable_password' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Set the password manually')
            ),
            'enabled' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'encrypt' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('When uploading malicious samples, set this flag to tell MISP to encrypt the sample and extract the file hashes. This will create a MISP object with the appropriate attributes.')
            ),
            //'enforceWarningList' => array(
            //    'input' => 'radio',
            //    'type' => 'integer',
            //    'values' => array(1 => 'True', 0 => 'False' )
            //),
            'enforceWarninglist' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Should the warning list be enforced. Adds `blocked` field for matching attributes')
            ),
            'event' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
		'validation' => array('min' => 0, 'step' => 1),
		'help' => __('Event id')
            ),
            'event_id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1)
            ),
            'event_timestamp' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1),
                'help' => __('The timestamp at which the event was last modified')
            ),
            'attribute_timestamp' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1),
                'help' => __('The timestamp at which the attribute was last modified')
            ),
            'eventid' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1)
            ),
            'eventinfo' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('Quick event description')
            ),
            'exportable' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The tag is exported when synchronising with other instances')
            ),
            'excludeDecayed' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => 'Should the decayed elements by excluded'
            ),
            'excludeLocalTags' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Exclude local tags from the export')
            ),
            'extend' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The organisation have write access to this sharing group (they can add/remove other organisation)')
            ),
            'external_auth_required' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('An external authorisation is required for this user')
            ),
            'external_auth_key' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('A valid external auth key')
            ),
            'first_seen' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => 'A valid ISO 8601 datetime format, up to milli-seconds. i.e.: 2019-06-13T15:56:56.856074+02:00'
            ),
            'fixed_event' => array(
                'input' => 'select',
                'type' => 'integer',
                'operators' => array('equal'),
                'values' => array( 0 => 'New Event Each Pull', 1 => 'Fixed Event'),
                'help' => __('target_event option might be considered')
            ),
            'from' => array(
                'type' => 'date',
                'validation' => array( 'format' => 'YYYY-MM-DD' ),
                'plugin' => 'datepicker',
                'plugin_config' => array(
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ),
                'help' => __('The date from which the event was published')
            ),
            'galaxy_cluster_uuid' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => __('Source galaxy cluster UUID')
            ),
            'gpgkey' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('A valid GPG key')
            ),
            'hasproposal' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The event contains proposals')
            ),
            'headers' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Headers to be passed with the requests. All separated by `\n`')
            ),
            'hide_tag' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The tag is hidden (not selectable)')
            ),
            'id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1)
            ),
            'includeAttribute' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Include matching attributes in the response')
            ),
            'includeDecayScore' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => 'Include all enabled decaying score'
            ),
            'includeEvent' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Include matching events in the response')
            ),
            'includeEventUuid' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Include matching eventUuids in the response')
            ),
            'includeEventTags' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Include tags of matching events in the response')
            ),
            'includeFullModel' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => 'Include all model information of matching events in the response'
            ),
            'includeProposals' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Include proposals of matching events in the response')
            ),
            'info' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('Quick event description')
            ),
            'input_source' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal'),
                'values' => array( 'network' => 'Network', 'local' => 'Local'),
                'help' => __('Specify whether the source (url field) is a directory (local) or an geniun url (network)')
            ),
            'ip' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The IP of a login attempt')
            ),
            'json' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('JSON containing ID, UUID and name')
            ),
            'last' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m)')
            ),
            'last_seen' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => 'A valid ISO 8601 datetime format, up to milli-seconds. i.e.: 2019-06-13T15:56:56.856074+02:00'
            ),
            'limit' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
                'help' => __('Limit on the pagination')
            ),
            'local' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('If the organisation should have access to this instance, make sure that the Local organisation setting is checked. If you would only like to add a known external organisation for inclusion in sharing groups, uncheck the Local organisation setting.')
            ),
            'lookup_visible' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The lookup will not be visible in the feed correlation')
            ),
            'message' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('Message to be included')
            ),
            'metadata' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Will only return the metadata of the given query scope, contained data is omitted.')
            ),
            'minimal' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Will only return  id, timestamp, published and uuid')
            ),
            'mock' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'operators' => array('equal'),
                'help' => __('Mock the query')
            ),
            'model' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal'),
                'values' => array('Attribute', 'Event', 'EventBlocklist', 'EventTag', 'MispObject', 'Organisation', 'Post', 'Regexp', 'Role', 'Server', 'ShadowAttribute', 'SharingGroup', 'Tag', 'Task', 'Taxonomy', 'Template', 'Thread', 'User', 'Whitelist'),
            ),
            'model_id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
            ),
            'modified' => array(
                'type' => 'date',
                'validation' => array( 'format' => 'YYYY-MM-DD' ),
                'plugin' => 'datepicker',
                'plugin_config' => array(
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ),
                'help' => __('The last time the sharing group was modified')
            ),
            'name' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
            ),
            'nationality' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal'),
                'values' => array('nat1'),
            ),
            'newsread' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
                'help' => __('The news are read')
            ),
            'nids_sid' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
                'help' => __('The unique Signature Identification')
            ),
            'org' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('Can be either the ORG_ID or the ORG_NAME')
            ),
            'org_description' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('Describe the organisation')
            ),
            'org_name' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('Organisation identifier (name)')
            ),
            'org_id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
            ),
            'org_uuid' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Globally used uuid of an organisation')
            ),
            'organisation_uuid' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Globally used uuid of an organisation')
            ),
            'override_ids' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The IDS flags will be set to off for this feed')
            ),
            'page' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 1, 'step' => 1),
                'help' => __('Page number for the pagination')
            ),
            'password' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The hardcoded password')
            ),
            'perm_admin' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_audit' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_auth' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_delegate' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_regexp_access' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_sharing_group' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_sighting' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_site_admin' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_sync' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_tag_editor' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_tagger' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_galaxy_editor' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'perm_template' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'permission' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal'),
                'values' => array(0 =>'Read Only', 1 => 'Manage Own Events', 2 => 'Manage Organisation Events', 3 => 'Manage and Publish Organisation Events'),
            ),
            'provider' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('The name of the feed provider')
            ),
            'publish' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('The event will be published')
            ),
            'publish_timestamp' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1)
            ),
            'published' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'publishtimestamp' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1)
            ),
            'pull' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Allow the download of events and their attribute from the server')
            ),
            'push' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Allow the upload of events and their attribute to the server')
            ),
            'push_sightings' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Allow the upload of sightings to the server')
            ),
            'referenced_galaxy_cluster_uuid' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Destination galaxy cluster UUID')
                ),
            'referenced_galaxy_cluster_type' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The type of the relation. Example: `is`, `related-to`, ...')
            ),
            'releasability' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Concise summary for who this sharing group is releasable to')
            ),
            'remote_org_id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
            ),
            'returnFormat' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal'),
                'values' => array('json', 'openioc', 'xml', 'suricata', 'snort', 'text', 'rpz', 'csv', 'cache', 'stix', 'stix2'),
            ),
            'roaming' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Pass the event to any connected instance where the sync connection is tied to an organisation contained in the SG organisation list')
            ),
            'role_id' => array(
                'input' => 'select',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array(0 => 'role1'),
            ),
            'score' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1, 'max' => 100),
                'help' => 'An alias to override on-the-fly the threshold of the decaying model'
            ),
            'searchall' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields')
            ),
            'sector' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The sector of the organisation')
            ),
            'server_id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
            ),
            'sgReferenceOnly' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Will only return the sharing group ID')
            ),
            'sharing_group_id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1)
            ),
            'sharinggroup' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1),
                'help' => __('Sharing group ID')
            ),
            'source' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The source of the Sighting (e.g. honeypot_1)')
            ),
            'source_format' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'values' => array( 'misp' => 'MISP Feed', 'freetext' => 'Freetext Parsed Feed', 'csv' => 'CSV Parsed Feed')
            ),
            'strict_tag_name_only' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'help' => __('Only returns tags matching exactly the tag name (thus skipping synonyms and cluster\'s value)')
            ),
            'subject' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The email\'s subject')
            ),
            'submitted_cert' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Base64 encoded certificate')
            ),
            'submitted_client_cert' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Base64 encoded certificate')
            ),
            'sync' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' ),
                'operators' => array('equal')
            ),
            'tag' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
            ),
            'tag_id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
                'help' => __('A tad ID to attach to created events')
            ),
            'tags' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'unique' => false,
            ),
            'target_event' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
                'help' => __('The provided ID will be reused as an existing event')
            ),
            'termsaccepted' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),
            'threat_level_id' => array(
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'values' => array( 1 => 'High', 2 => 'Medium', 3 => 'Low', 4 => 'Undefined')
            ),
            'threatlevel' => array(
                'input' => 'select',
                'type' => 'integer',
                'operators' => ['equal', 'not_equal'],
                'values' => array( 1 => 'High', 2 => 'Medium', 3 => 'Low', 4 => 'Undefined')
            ),
            'time' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Time of the sighting with the form `h:i:s`')
            ),
            'timestamp' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal', 'not_equal'),
                'validation' => array('min' => 0, 'step' => 1)
            ),
            'title' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('The title of the log')
            ),
            'to' => array(
                'type' => 'date',
                'validation' => array( 'format' => 'YYYY-MM-DD' ),
                'plugin' => 'datepicker',
                'plugin_config' => array(
                    'format' => 'yyyy/mm/dd',
                    'todayBtn' => 'linked',
                    'todayHighlight' => true,
                    'autoclose' => true
                ),
                'help' => __('The date to which the event was published')
            ),
            'to_ids' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False'),
                'help' => __('The state of the `to_ids` flag')
            ),
            'type' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
                'help' => __('The type of the attribute')
            ),
            'url' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal'),
            ),
            'user_id' => array(
                'input' => 'number',
                'type' => 'integer',
                'operators' => array('equal'),
                'validation' => array('min' => 0, 'step' => 1),
            ),
            'uuid' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal')
            ),
            'value' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal', 'not_equal')
            ),
            'values' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'unique' => false,
                'help' => __('Placeholder containing values to sight')
            ),
            'withAttachments' => array(
                'input' => 'radio',
                'type' => 'integer',
                'values' => array(1 => 'True', 0 => 'False' )
            ),

            // Not supported yet
            '[]' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported (warninglist->checkvalues) expect an array')
            ),
            'push_rules' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),
            'pull_rules' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),
            'rules' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),

            'settings' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),
            'network_name' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),
            'network_json' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),
            'Attribute' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),
            'Object' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),
            'EventTag' => array(
                'input' => 'select',
                'type' => 'string',
                'operators' => array('equal'),
            ),
            'Shadow_Attribute' => array(
                'input' => 'text',
                'type' => 'string',
                'operators' => array('equal'),
                'help' => __('Not supported')
            ),
        );
    }

    // create dictionnary mapping between fields constraints and scope->action
    private function __setupFieldsConstraint() {
        foreach ($this->__descriptions as $scope => $desc) {
            foreach ($desc as $action => $params) {
                $fieldsConstraint = array();
                foreach ($params as $paramType => $field) {
                    if ($paramType == 'optional' || $paramType == 'mandatory') {
                        $fields = array_values($field);
                        if (!empty($fields)) {
                            foreach($fields as $field) {
                                if (is_array($field)) {
                                    foreach($field as $sf) {
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
                                switch($field) {
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
                                    case "attribute":
                                        $this->__overwriteAttribute($scope, $action, $fieldsConstraint[$field]);
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
    private function __overwriteReturnFormat($scope, $action, &$field) {
        switch($scope) {
            case "Attribute":
            case "Event":
                $field['values'] = array_keys(ClassRegistry::init($scope)->validFormats);
                break;
        }
    }
    private function __overwriteType($scope, $action, &$field) {
        $field['input'] = 'select';
        switch($scope) {
            case "Attribute":
                $field['values'] = array_keys(ClassRegistry::init($scope)->typeDefinitions);
                break;
            case "Event":
                $field['values'] = array_keys(ClassRegistry::init("Attribute")->typeDefinitions);
                break;
            case "Sighting":
                $field['values'] = ClassRegistry::init($scope)->type;
                break;
            default:
                $field['input'] = 'text';
                break;
        }
    }

    private function __overwriteCategory($scope, $action, &$field) {
        $field['values'] = array_keys(ClassRegistry::init("Attribute")->categoryDefinitions);
    }
    private function __overwriteDistribution($scope, $action, &$field) {
        $field['values'] = array();
        foreach(ClassRegistry::init("Attribute")->distributionLevels as $d => $text) {
            $field['values'][] = array('label' => $text, 'value' => $d);
        }
    }
    private function __overwriteDecayingModel($scope, &$field) {
        $this->{$scope} = ClassRegistry::init("DecayingModel");
        $models = $this->{$scope}->find('list', array(
            'recursive' => -1,
            'fields' => array('name')
        ));
        $field['values'] = array();
        foreach($models as $i => $model_name) {
            $field['values'][] = array('label' => h($model_name), 'value' => $i);
        }
    }

    private function __overwriteTags($scope, $action, &$field)
    {
        static $values;
        if ($values === null) {
            $tagModel = ClassRegistry::init("Tag");
            $tags = $tagModel->find('column', array(
                'fields' => array('Tag.name')
            ));
            $values = [];
            foreach ($tags as $tag) {
                $tagname = htmlspecialchars($tag);
                $values[$tagname] = $tagname;
            }
        }
        $field['values'] = $values;

        if ($action == 'attachTagToObject') {
            $field['help'] = __('Also supports array of tags');
        }
    }
    private function __overwriteAttribute($scope, $action, &$field){
        if ($action == 'addTag' || $action == 'removeTag') {
            $field['help'] = __('Attribute id');
        }
    }
    private function __overwriteNationality($scope, $action, &$field) {
        $field['values'] = ClassRegistry::init("Organisation")->getCountries();
    }
    private function __overwriteAction($scope, $action, &$field) {
        $field['values'] = array_keys(ClassRegistry::init("Log")->actionDefinitions);
    }
    private function __overwriteRoleId($scope, $action, &$field) {
        $this->{$scope} = ClassRegistry::init("Role");
        $roles = $this->{$scope}->find('list', array(
            'fields' => array('id', 'name')
        ));
        $field['values'] = [];
        foreach ($roles as $id => $name) {
            $field['values'][] = ['label' => $name, 'value' => $id];
        }
    }
    private function __overwriteSeen($scope, $action, &$field) {
        if ($action == 'restSearch') {
            $field['help'] = __('Seen within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m)');
        }
    }
}
