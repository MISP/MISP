<?php

class RestResponseComponent extends Component {
	
	public function saveFailResponse($model, $action, $id = false, $validationErrors, $format) {
		$this->autoRender = false;
		$response = array();
		$action = $this->__dissectAdminRouting($action);
		$response['name'] = 'Could not ' . $action['action'] . ' ' . $model;
		$response['message'] = $response['name'];
		$response['url'] = $this->__generateURL($action, $model, $id);
		$response['errors'] = $validationErrors;
		return $this->__sendResponse($response, 403, $format);	
	}
	
	public function saveSuccessResponse($model, $action, $id = false, $format) {
		$action = $this->__dissectAdminRouting($action);
		$response['name'] = $model . ' ' . $action['action'] . 'ed';
		$response['message'] = $response['name'];
		$this->__generateURL($action, $model, $id); 
		$response['url'] = $this->__generateURL($action, $model, $id);
		return $this->__sendResponse($response, 200, $format);
	}
	
	private function __sendResponse($response, $code, $format) {
		if (strtolower($format) === 'application/xml') {
			$response = Xml::build($response);
			$type = 'xml';
		} else {
			$response = json_encode($response, JSON_PRETTY_PRINT);
			$type = 'json';
		}
		return new CakeResponse(array('body'=> $response,'status' => $code, 'type' => $type));
	}
	
	private function __generateURL($action, $model, $id) {
		return ($action['admin'] ? '/admin' : '') . '/' . strtolower(Inflector::pluralize($model)) . '/' . $action['action'] . ($id ? '/' . $id : '');
	}
	
	private function __dissectAdminRouting($action) {
		$admin = false;
		if (strlen($action) > 6 && substr($action, 0, 6) == 'admin_') {
			$action = substr($action, 6);
			$admin = true;
		}
		return array('action' => $action, 'admin' => $admin);
	}
	
	public function saveSuccessData($data, $format) {
		return $this->__sendResponse($data, 200, $format);
	}
}
