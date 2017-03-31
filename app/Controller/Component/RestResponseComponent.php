<?php

class RestResponseComponent extends Component {

	private $__descriptions = array(
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
			'Organisation' => array(
				'admin_add' => array(
					'description' => "POST an Organisation object in JSON format to this API to create a new organsiation.",
					'mandatory' => array('name'),
					'optional' => array('anonymise', 'description', 'type', 'nationality', 'sector', 'uuid', 'contacts', 'local')
				),
				'admin_edit' => array(
					'description' => "POST an Organisation object in JSON format to this API to create a new organsiation.",
					'mandatory' => array('name'),
					'optional' => array('anonymise', 'description', 'type', 'nationality', 'sector', 'uuid', 'contacts', 'local')
				)
			),
			'Server' => array(
				'add' => array(
					'description' => "POST an Server object in JSON format to this API to add a server.",
					'mandatory' => array('url', 'name', 'organisation_type', 'authkey', 'json'),
					'optional' => array('push', 'pull', 'push_rules', 'pul_rules', 'submitted_cert', 'submitted_client_cert')
				),
				'edit' => array(
					'description' => "POST an Server object in JSON format to this API to edit a server.",
					'optional' => array('url', 'name', 'organisation_type', 'authkey', 'json', 'push', 'pull', 'push_rules', 'pul_rules', 'submitted_cert', 'submitted_client_cert')
				)
			)
	);

	public function saveFailResponse($controller, $action, $id = false, $validationErrors, $format = false) {
		$this->autoRender = false;
		$response = array();
		$action = $this->__dissectAdminRouting($action);
		$response['name'] = 'Could not ' . $action['action'] . ' ' . Inflector::singularize($controller);
		$response['message'] = $response['name'];
		$response['url'] = $this->__generateURL($action, $controller, $id);
		$response['errors'] = $validationErrors;
		return $this->__sendResponse($response, 403, $format);
	}

	public function saveSuccessResponse($controller, $action, $id = false, $format = false, $message = false) {
		$action = $this->__dissectAdminRouting($action);
		if (!$message) {
			$message = Inflector::singularize($controller) . ' ' . $action['action'] . ((substr($action['action'], -1) == 'e') ? 'd' : 'ed');
		}
		$response['name'] = $message;
		$response['message'] = $response['name'];
		$response['url'] = $this->__generateURL($action, $controller, $id);
		return $this->__sendResponse($response, 200, $format);
	}

	private function __sendResponse($response, $code, $format = false, $raw = false) {
		if (strtolower($format) === 'application/xml') {
			if (!$raw) $response = Xml::build($response);
			$type = 'xml';
		} else if(strtolower($format) == 'openioc') {
			$type = 'xml';
		} else {
			if (!$raw) $response = json_encode($response, JSON_PRETTY_PRINT);
			$type = 'json';
		}
		return new CakeResponse(array('body'=> $response,'status' => $code, 'type' => $type));
	}

	private function __generateURL($action, $controller, $id) {
		return ($action['admin'] ? '/admin' : '') . '/' . strtolower($controller) . '/' . $action['action'] . ($id ? '/' . $id : '');
	}

	private function __dissectAdminRouting($action) {
		$admin = false;
		if (strlen($action) > 6 && substr($action, 0, 6) == 'admin_') {
			$action = substr($action, 6);
			$admin = true;
		}
		return array('action' => $action, 'admin' => $admin);
	}

	public function viewData($data, $format = false, $errors = false, $raw = false) {
		if (!empty($errors)) {
			$data['errors'] = $errors;
		}
		return $this->__sendResponse($data, 200, $format, $raw);
	}

	public function describe($controller, $action, $id = false, $format = false) {
		$actionArray = $this->__dissectAdminRouting($action);
		$response['name'] = $this->__generateURL($actionArray, $controller, false) . ' API description';
		$response['description'] = isset($this->__descriptions[Inflector::singularize($controller)][$action]['description']) ? $this->__descriptions[Inflector::singularize($controller)][$action]['description'] : 'This API is not accessible via GET requests.';
		if (isset($this->__descriptions[Inflector::singularize($controller)][$action]['mandatory'])) {
			$response['mandatory_fields'] = $this->__descriptions[Inflector::singularize($controller)][$action]['mandatory'];
		}
		if (isset($this->__descriptions[Inflector::singularize($controller)][$action]['optional'])) {
			$response['optional_fields'] = $this->__descriptions[Inflector::singularize($controller)][$action]['optional'];
		}
		$response['url'] = $this->__generateURL($actionArray, $controller, $id);
		return $this->__sendResponse($response, 200, $format);
	}
}
