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
			$message = Inflector::singularize($controller) . ' ' . $action['action'] . 'ed';
		}
		$response['name'] = $message;
		$response['message'] = $response['name'];
		$response['url'] = $this->__generateURL($action, $controller, $id);
		return $this->__sendResponse($response, 200, $format);
	}

	private function __sendResponse($response, $code, $format = false) {
		if (strtolower($format) === 'application/xml') {
			$response = Xml::build($response);
			$type = 'xml';
		} else {
			$response = json_encode($response, JSON_PRETTY_PRINT);
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

	public function viewData($data, $format = false) {
		return $this->__sendResponse($data, 200, $format);
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
