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

    private $__descriptions = array(
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
					Besides the parameters listed, other, format specific ones can be passed along.
					Accepted return formats are: [json, xml, suricata, snort, text, openioc, rpz]",
				'mandatory' => array('returnFormat'),
				'optional' => array('value' , 'type', 'category', 'org', 'tags', 'from', 'to', 'last', 'eventid', 'withAttachments', 'uuid', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'to_ids', 'deleted', 'includeEventUuid', 'event_timestamp', 'threat_level_id'),
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
			'restSearch' => array(
				'description' => "Search MISP using a list of filter parameters and return the data
					in the selected format. The search is available on an event and an attribute level,
					just select the scope via the URL (/events/restSearch vs /attributes/restSearch).
					Besides the parameters listed, other, format specific ones can be passed along.
					Accepted return formats are: [json, xml, suricata, snort, text, openioc, rpz]",
				'mandatory' => array('returnFormat'),
				'optional' => array('value', 'type', 'category', 'org', 'tag', 'tags', 'searchall', 'from', 'to', 'last', 'eventid', 'withAttachments', 'metadata', 'uuid', 'published', 'publish_timestamp', 'timestamp', 'enforceWarninglist', 'sgReferenceOnly'),
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
            )
        ),
        'Sighting' => array(
            'add' => array(
                'description' => "POST a simplified sighting object in JSON format to this API to add a or a list of sightings. Pass either value(s) or attribute IDs (can be uuids) to identify the target sightings.",
                'mandatory' => array('OR' => array('values', 'id')),
                'optional' => array('type', 'source', 'timestamp', 'date', 'time')
            )
        ),
        'SharingGroup' => array(
            'add' => array(
                'description' => "POST a Sharing Group object in JSON format to this API to add a Sharing Group. The API will also try to capture attached organisations and servers if applicable to the current user.",
                'mandatory' => array('name', 'releasability'),
                'optional' => array('description', 'uuid', 'organisation_uuid (sync/site admin only)', 'active', 'created', 'modified', 'roaming', 'Server' => array('url', 'name', 'all_orgs'), 'Organisation' => array('uuid', 'name', 'extend'))
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
                'description' => "POST a request object in JSON format to this API to create detach a tag from an event.",
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
			'toggleEnable' => array(
				'description' => "POST a json object with a single or a list of warninglist IDsIDs, or alternatively a (list of) substring(s) that match the names of warninglist(s) to toggle whether they're enabled or disabled. Specify the optional enabled boolean flag if you would like to enforce the outcome state. Not setting this flag will just toggle the current state.",'mandatory' => array('id'),
				'optional' => array('id', 'name', 'enabled')
			)
		)
    );

	public function getAllApis($user, $Server)
	{
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

	// use a relative path to check if the current api has a description
	public function getApiInfo($relative_path)
	{
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
        if (strtolower($format) === 'application/xml') {
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
        $cakeResponse = new CakeResponse(array('body'=> $response,'status' => $code, 'type' => $type));
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
}
