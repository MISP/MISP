<?php

class RestResponseComponent extends Component
{
    private $__convertActionToMessage = array(
        'SharingGroup' => array(
            'addOrg' => 'add Organisation to',
            'removeOrg' => 'remove Organisation from',
            'addServer' => 'add Server to',
            'removeServer' => 'remove Server from'
        )
    );

	private $___setup = false;

    public $__descriptions = array(
        'Attribute' => array(
            'add' => array(
                'description' => "POST a MISP Attribute JSON to this API to create an Attribute.",
                'mandatory' => array('value', 'type'),
                'optional' => array('category', 'to_ids', 'uuid', 'distribution', 'sharing_group_id', 'timestamp', 'comment'),
                'params' => array('event_id')
            ),
            'edit' => array(
                'description' => "POST a MISP Attribute JSON to this API to update an Attribute. If the timestamp is set, it has to be newer than the existing Attribute.",
                'mandatory' => array(),
                'optional' => array('value', 'type', 'category', 'to_ids', 'uuid', 'distribution', 'sharing_group_id', 'timestamp', 'comment'),
                'params' => array('event_id')
            ),
            'deleteSelected' => array(
                'description' => "POST a list of attribute IDs in JSON format to this API
					to delete the given attributes. This API also expects an event ID passed via
					the URL or via the event_id key. The id key also takes 'all' as a parameter
					for a wildcard search to mass delete attributes. If you want the function to
					also hard-delete already soft-deleted attributes, pass the allow_hard_delete
					key.",
                'mandatory' => array('id'),
                'optional' => array('event_id', 'allow_hard_delete'),
                'params' => array('event_id')
            ),
			'restSearch' => array(
				'description' => "Search MISP using a list of filter parameters and return the data
					in the selected format. The search is available on an event and an attribute level,
					just select the scope via the URL (/events/restSearch vs /attributes/restSearch).
					Besides the parameters listed, other, format specific ones can be passed along (for example: requested_attributes and includeContext for the CSV export).
					This API allows pagination via the page and limit parameters.",
				'mandatory' => array('returnFormat'),
				'optional' => array('page', 'limit', 'value' , 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'to_ids', 'deleted', 'includeEventUuid', 'includeEventTags', 'event_timestamp', 'threat_level_id', 'eventinfo'),
				'params' => array()
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
				'description' => "Search MISP using a list of filter parameters and return the data
					in the selected format. The search is available on an event and an attribute level,
					just select the scope via the URL (/events/restSearch vs /attributes/restSearch).
					Besides the parameters listed, other, format specific ones can be passed along (for example: requested_attributes and includeContext for the CSV export).
					This API allows pagination via the page and limit parameters.",
				'mandatory' => array('returnFormat'),
				'optional' => array('page', 'limit', 'value', 'type', 'category', 'org', 'tag', 'tags', 'searchall', 'from', 'to', 'last', 'eventid', 'withAttachments', 'metadata', 'uuid', 'published', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'sgReferenceOnly', 'eventinfo'),
				'params' => array()
			)
        ),
		'EventGraph' => array(
			'add' => array(
				'description' => "POST a network in JSON format to this API to to keep an history of it",
				'mandatory' => array('event_id', 'network_json'),
				'optional' => array('network_name')
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
                'optional' => array('push', 'pull', 'push_rules', 'pull_rules', 'submitted_cert', 'submitted_client_cert', 'json')
            ),
            'edit' => array(
                'description' => "POST an Server object in JSON format to this API to edit a server.",
                'optional' => array('url', 'name', 'authkey', 'json', 'push', 'pull', 'push_rules', 'pull_rules', 'submitted_cert', 'submitted_client_cert', 'remote_org_id')
            ),
			'serverSettings' => array(
				'description' => "Send a GET request to this endpoint to get a full diagnostic along with all currently set settings of the current instance."
			)
        ),
        'Sighting' => array(
            'add' => array(
                'description' => "POST a simplified sighting object in JSON format to this API to add a or a list of sightings. Pass either value(s) or attribute IDs (can be uuids) to identify the target sightings.",
                'mandatory' => array('OR' => array('values', 'id')),
                'optional' => array('type', 'source', 'timestamp', 'date', 'time')
            ),
            'restSearch' => array(
                'description' => "Search MISP sightings using a list of filter parameters and return the data in the JSON format.
                    The search is available on an event, attribute or instance level,
                    just select the scope via the URL (/sighting/restSearch/event vs /sighting/restSearch/attribute vs /sighting/restSearch/).
                    id MUST be provided if context is set.",
                'mandatory' => array('returnFormat'),
                'optional' => array('id', 'type', 'from', 'to', 'last', 'org_id', 'source', 'includeAttribute', 'includeEvent'),
                'params' => array('context')
            ),
        ),
        'SharingGroup' => array(
            'add' => array(
                'description' => "POST a Sharing Group object in JSON format to this API to add a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.",
                'mandatory' => array('AND' => array('name', 'releasability')),
                'optional' => array('description', 'uuid', 'organisation_uuid (sync/site admin only)', 'active', 'created', 'modified', 'roaming', 'Server #FIXME API help display not working' => array('url', 'name', 'all_orgs'), 'Organisation' => array('uuid', 'name', 'extend'))
            ),
            'edit' => array(
                'description' => "POST a Sharing Group object in JSON format to this API to edit a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.",
                'mandatory' => array(),
                'optional' => array('name', 'releasability', 'description', 'uuid', 'organisation_uuid (sync/site admin only)', 'active', 'created', 'modified', 'roaming', 'SharingGroupServer' => array('url', 'name', 'all_orgs'), 'SharingGroupOrg' => array('uuid', 'name', 'extend'))
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
            'removeTag' => array(
                'description' => "POST a request object in JSON format to this API to create detach a tag from an event. #FIXME Function does not exists",
                'mandatory' => array('event', 'tag'),
                'params' => array('tag_id')
            ),
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

    public $__scopedFieldsConstraint = array();


	public function getAllApis($user, $Server)
	{
		$this->__setup();
		$result = array();
		foreach ($this->__descriptions as $controller => $actions) {
			$controller = Inflector::tableize($controller);
			foreach ($actions as $action => $data) {
				if ($Server->ACL->checkAccess($user, $controller, $action, true) === true) {
					$admin_routing = '';
					if (substr($action, 0, 6) === 'admin_') {
						$action = substr($action, 6);
						$admin_routing = 'admin/';
					}
					$data['api_name'] = '[' . $controller . '] ' . $action;
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

	public function getAllApisFieldsConstraint($user, $Server)
	{
		$this->__setup();
		$result = array();
		foreach ($this->__scopedFieldsConstraint as $controller => $actions) {
			$controller = Inflector::tableize($controller);
			foreach ($actions as $action => $data) {
				if ($Server->ACL->checkAccess($user, $controller, $action, true) === true) {
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
				$temp = array();
			}
			if (empty($temp)) return '[]';
			return json_encode(array('api_info' => $temp));
		}
		return '[]';
	}

    public function saveFailResponse($controller, $action, $id = false, $validationErrors, $format = false)
    {
        $this->autoRender = false;
        $response = array();
        $action = $this->__dissectAdminRouting($action);
        $stringifiedAction = $action['action'];
        if (isset($this->__convertActionToMessage[$controller][$action['action']])) {
            $stringifiedAction = $this->__convertActionToMessage[$controller][$action['action']];
        }
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
        $response['name'] = $message;
        $response['message'] = $response['name'];
        $response['url'] = $this->__generateURL($action, $controller, $id);
        return $this->__sendResponse($response, 200, $format);
    }

    private function __sendResponse($response, $code, $format = false, $raw = false, $download = false)
    {
        if (strtolower($format) === 'application/xml' || strtolower($format) === 'xml') {
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
                $response = Xml::build($response);
                $response = $response->asXML();
            }
            $type = 'xml';
        } elseif (strtolower($format) == 'openioc') {
            $type = 'xml';
        } elseif (strtolower($format) == 'csv') {
            $type = 'csv';
        } else {
            if (!$raw) {
                $response = json_encode($response, JSON_PRETTY_PRINT);
            }
            $type = 'json';
        }
        $cakeResponse = new CakeResponse(array('body'=> $response, 'status' => $code, 'type' => $type));
        if ($download) {
            $cakeResponse->download($download);
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
        return array('action' => $action, 'admin' => $admin);
    }

    public function viewData($data, $format = false, $errors = false, $raw = false, $download = false)
    {
        if (!empty($errors)) {
            $data['errors'] = $errors;
        }
        return $this->__sendResponse($data, 200, $format, $raw, $download);
    }

	public function sendFile($path, $format = false, $download = false, $name = 'download') {
		$cakeResponse = new CakeResponse(array(
			'status' => 200,
			'type' => $format
		));
		$cakeResponse->file($path, array('name' => $name, 'download' => true));
		return $cakeResponse;
	}

    public function throwException($code, $message, $url = '', $format = false, $raw = false)
    {
        $message = array(
            'name' => $message,
            'message' => $message,
            'url' => $url
        );
        return $this->__sendResponse($message, $code, $format, $raw);
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

	private function __setup() {
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
            $this->__setupFieldsConstraint();
		}
		return true;
	}


    // default value and input for API field
    private $__fieldsConstraint = array(
        'action' => array(
            'input' => 'select',
            'type' => 'string',
            'operators' => array('equal'),
            'values' => array('action1'),
        ),
        'active' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'all' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'all_orgs' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'allow_hard_delete' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'analysis' => array(
            'input' => 'select',
            'type' => 'integer',
            'operators' => array('equal', 'not_equal'),
            'values' => array( 0 => 'Initial', 1 => 'Ongoing', 2 => 'Completed')
        ),
        'attribute' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal', 'not_equal'),
            'help' => 'Filter on attribute value'
        ),
        'authkey' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
        ),
        'autoalert' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'body' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
        ),
        'caching_enabled' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'category' => array(
            'input' => 'select',
            'type' => 'string',
            'operators' => array('equal', 'not_equal'),
            'values' => array('categ1')
        ),
        'certif_public' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'A valid x509 certificate '
        ),
        'change' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
        ),
        'change_pw' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'colour' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'A valid hexadecimal colour `#ffffff`',
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
        ),
        'contactalert' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'created' => array(
            'input' => 'number',
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
        'date' => array(
            'input' => 'number',
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
        'datefrom' => array(
            'input' => 'number',
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
            'input' => 'number',
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
        'default_role' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'delete_local_file' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'deleted' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'delta_merge' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'description' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
        ),
        'disabled' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'distribution' => array(
            'input' => 'select',
            'type' => 'integer',
            'operators' => ['equal', 'not_equal'],
            'values' => array(0 => 'dist1')
        ),
        'email' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal', 'not_equal'),
            'help' => 'Filter on user email'
        ),
        'enable_password' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'enabled' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'enforceWarningList' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'enforceWarninglist' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
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
            'validation' => array('min' => 0, 'step' => 1)
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
            'operators' => array('equal', 'not_equal')
        ),
        'exportable' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'extend' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'external_auth_required' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'external_auth_key' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'A valid auth key',
        ),
        'fixed_event' => array(
            'input' => 'select',
            'type' => 'integer',
            'operators' => array('equal'),
            'values' => array( 0 => 'New Event Each Pull', 1 => 'Fixed Event'),
            'help' => 'target_event option might be considered'
        ),
        'from' => array(
            'input' => 'number',
            'type' => 'integer',
            'operators' => array('equal', 'not_equal'),
            'validation' => array('min' => 0, 'step' => 1)
        ),
        'gpgkey' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'A valid GPG '
        ),
        'hasproposal' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'headers' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Headers to be passed with the requests. All separated by `\n`'
        ),
        'hide_tag' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
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
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'includeEvent' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'includeEventUuid' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'includeEventTags' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'info' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal', 'not_equal')
        ),
        'input_source' => array(
            'input' => 'select',
            'type' => 'string',
            'operators' => array('equal'),
            'values' => array( 'network' => 'Network', 'local' => 'Local')
        ),
        'ip' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
        ),
        'json' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'JSON containing ID, UUID and name',
        ),
        'last' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal', 'not_equal')
        ),
        'limit' => array(
            'input' => 'number',
            'type' => 'integer',
            'operators' => array('equal', 'not_equal'),
            'validation' => array('min' => 0, 'step' => 1)
        ),
        'local' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'lookup_visible' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'metadata' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' ),
            'help' => 'Will not return Attributes, shadow attribute and objects'
        ),
        'minimal' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' ),
            'help' => 'Will only return  id, timestamp, published and uuid'
        ),
        'model' => array(
            'input' => 'select',
            'type' => 'string',
            'operators' => array('equal'),
            'values' => array('Attribute', 'Event', 'EventBlacklist', 'EventTag', 'MispObject', 'Organisation', 'Post', 'Regexp', 'Role', 'Server', 'ShadowAttribute', 'SharingGroup', 'Tag', 'Task', 'Taxonomy', 'Template', 'Thread', 'User', 'Whitelist'),
        ),
        'model_id' => array(
            'input' => 'number',
            'type' => 'integer',
            'operators' => array('equal'),
            'validation' => array('min' => 0, 'step' => 1),
        ),
        'modified' => array(
            'input' => 'number',
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
        ),
        'nids_sid' => array(
            'input' => 'number',
            'type' => 'integer',
            'operators' => array('equal'),
            'validation' => array('min' => 0, 'step' => 1),
        ),
        'org' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal', 'not_equal'),
            'help' => 'Can be either the ORG_ID or the ORG_NAME'
        ),
        'org_id' => array(
            'input' => 'number',
            'type' => 'integer',
            'operators' => array('equal'),
            'validation' => array('min' => 0, 'step' => 1),
        ),
        'organisation_uuid (sync/site admin only)' => array(
            'input' => 'number',
            'type' => 'integer',
            'operators' => array('equal'),
            'validation' => array('min' => 0, 'step' => 1),
        ),
        'override_ids' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'page' => array(
            'input' => 'number',
            'type' => 'integer',
            'operators' => array('equal', 'not_equal'),
            'validation' => array('min' => 0, 'step' => 1)
        ),
        'password' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
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
        ),
        'publish' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
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
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'push' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'releasability' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
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
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'role_id' => array(
            'input' => 'select',
            'type' => 'integer',
            'operators' => array('equal'),
            'validation' => array(0 => 'role1'),
        ),
        'searchall' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'sector' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
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
            'help' => 'Will only return the sharing group ID'
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
            'help' => 'Sharing group ID'
        ),
        'source' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
        ),
        'source_format' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'values' => array( 'misp' => 'MISP Feed', 'freetext' => 'Freetext Parsed Feed', 'csv' => 'CSV Parsed Feed')
        ),
        'subject' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
        ),
        'submitted_cert' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Base64 encoded certificate',
        ),
        'submitted_client_cert' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Base64 encoded certificate',
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
            'help' => 'A tad ID to attach to created events'
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
            'help' => 'The provided ID will be reused as an existing event'
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
            'values' => array( 1 => 'Hight', 2 => 'Medium', 3 => 'Low', 4 => 'Undefined')
        ),
        'threatlevel' => array(
            'input' => 'select',
            'type' => 'integer',
            'operators' => ['equal', 'not_equal'],
            'values' => array( 1 => 'Hight', 2 => 'Medium', 3 => 'Low', 4 => 'Undefined')
        ),
        'time' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Time of the form `h:i:s`',
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
        ),
        'to' => array(
            'input' => 'number',
            'type' => 'integer',
            'operators' => array('equal', 'not_equal'),
            'validation' => array('min' => 0, 'step' => 1)
        ),
        'to_ids' => array(
            'input' => 'radio',
            'type' => 'integer',
            'values' => array(1 => 'True', 0 => 'False' )
        ),
        'type' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal', 'not_equal'),
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
            'help' => 'An array containing values to sight. i.e. `[v1, v2]`',
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
            'help' => 'Not supported (warninglist->checkvalues) expect an array'
        ),
        'event' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported (removeTag)'
        ),
        'push_rules' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported'
        ),
        'pull_rules' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported'
        ),
        'rules' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported'
        ),

        'settings' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported'
        ),
        'network_name' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported'
        ),
        'network_json' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported'
        ),
        'Attribute' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported'
        ),
        'Object' => array(
            'input' => 'text',
            'type' => 'string',
            'operators' => array('equal'),
            'help' => 'Not supported'
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
            'help' => 'Not supported'
        ),
    );

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
                                    $fieldsConstraint[$field] = $this->__fieldsConstraint[$field];
                                    $label = $scope . '.' . $field;
                                    $fieldsConstraint[$field]['id'] = $label;
                                    $fieldsConstraint[$field]['label'] = $label;
                                }

                                // add dynamic data and overwrite name collisions
                                switch($field) {
                                    case "returnFormat":
                                        $this->__overwriteReturnFormat($scope, $fieldsConstraint[$field]);
                                        break;
                                    case "type":
                                        $this->__overwriteType($scope, $fieldsConstraint[$field]);
                                        break;
                                    case "category":
                                        $this->__overwriteCategory($scope, $fieldsConstraint[$field]);
                                        break;
                                    case "distribution":
                                        $this->__overwriteDistribution($scope, $fieldsConstraint[$field]);
                                        break;
                                    case "tag":
                                    case "tags":
                                    case "EventTag":
                                        $this->__overwriteTags($scope, $fieldsConstraint[$field]);
                                        break;
                                    case "nationality":
                                        $this->__overwriteNationality($scope, $fieldsConstraint[$field]);
                                        break;
                                    case "action":
                                        $this->__overwriteAction($scope, $fieldsConstraint[$field]);
                                        break;
                                    case "role_id":
                                        $this->__overwriteRoleId($scope, $fieldsConstraint[$field]);
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
    private function __overwriteReturnFormat($scope, &$field) {
        switch($scope) {
            case "Attribute":
                $field['values'] = array_keys(ClassRegistry::init($scope)->validFormats);
                break;
            case "Event":
                $field['values'] = array_keys(ClassRegistry::init($scope)->validFormats);
                break;
        }
    }
    private function __overwriteType($scope, &$field) {
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
    private function __overwriteCategory($scope, &$field) {
        $field['values'] = array_keys(ClassRegistry::init("Attribute")->categoryDefinitions);
    }
    private function __overwriteDistribution($scope, &$field) {
        $field['values'] = array_keys(ClassRegistry::init("Attribute")->distributionLevels);
    }
    private function __overwriteTags($scope, &$field) {
        $this->{$scope} = ClassRegistry::init("Tag");
        $tags = $this->{$scope}->find('list', array(
            'recursive' => -1,
            'fields' => array('name')
        ));
        $field['values'] = $tags;
    }
    private function __overwriteNationality($scope, &$field) {
        $field['values'] = array_keys(ClassRegistry::init("Organisation")->countries);
    }
    private function __overwriteAction($scope, &$field) {
        $field['values'] = array_keys(ClassRegistry::init("Log")->actionDefinitions);
    }
    private function __overwriteRoleId($scope, &$field) {
        $this->{$scope} = ClassRegistry::init("Role");
        $roles = $this->{$scope}->find('list', array(
            'recursive' => -1,
            'fields' => array('name')
        ));
        $field['values'] = $roles;
    }


}
