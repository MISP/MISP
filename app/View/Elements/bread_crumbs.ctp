<?php
$controller = $this->params['controller'];
$action = $this->params['action'];
$admin = '';
$extraInfo = '';
if (substr($action, 0, 5) === 'admin' || $this->params['admin']) $admin = '/admin';
// If we don't have a parameter set, then we just show the controller + action
if (isset ($this->params['pass'][0])) $modelID = $this->params['pass'][0];
// For certain actions, we want to show a different controller / modelID in the links
// For example: Clicking on "Add attribute", the breadcrumbs should look like this: home > Events > event_id > Add instead of home > Attributes > attribute_id > Add 
if (($controller === 'attributes' || $controller === 'shadow_attributes') && ($action === 'add' || $action === 'edit' || $action === 'add_attachment' || $action === 'add_threatconnect')) {
	// We still want to keep the info about the old Controller and in the case of an attribute edit the modelID, so we can show in the action portion of the breadcrumb what the action will affect. 
	// For example: home > Events > 1 > Edit Attribute(2)   This would mean that the 2nd attribute of the Event with ID 1 is being edited. 
	$extraInfo = ' ' . ucfirst(substr($controller, 0, -1));
	$controller = 'events';
	if ($action === 'edit' || $action === 'add_threatconnect') {
		if ($action === 'edit') $extraInfo .= '('.$modelID.')';
		// Even though it's an attribute action from an event, we actually don't want to keep the old controller name or the modelID for this one. 
		// add_threatconnect should show up like this: home > Event > Add_threatconnect
		else $extraInfo = '';
		$modelID = $this->request->data['Attribute']['event_id'];
	}
} elseif ($controller === 'logs' && $action === 'event_index') {
	$extraInfo = ' ' . ucfirst($controller);
	$controller = 'events';
	$modelID = $eventId;
} 
	$this->Html->addCrumb(ucfirst($controller), $admin.'/'.$controller );
	if (isset($modelID)) {
		if ($controller === 'regexp' || $controller === 'roles') {
			$this->Html->addCrumb($modelID);
		} else {
			$this->Html->addCrumb($modelID, $admin.'/'.$controller.'/'.'view'.'/'.$modelID);
		}
	}
	$actionArray = explode('_', $action);
	$action = '';
	foreach ($actionArray as $k => $current) {
		if ($k != 0) $action .= ' ';
		$action .= ucfirst($current);
	}
	$this->Html->addCrumb($action . $extraInfo);
?>