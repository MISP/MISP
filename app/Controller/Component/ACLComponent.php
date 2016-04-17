<?php
App::uses('Component', 'Controller');

class ACLComponent extends Component {

	private $__aclList = array(
			'*' => array(
					'blackhole' => array(),
					'checkAction' => array(),
					'checkAuthUser' => array(),
					'checkExternalAuthUser' => array(),
					'cleanModelCaches' => array(),
					'generateCount' => array(),
					'getActions' => array(),
					'pruneDuplicateUUIDs' => array(),
					'removeDuplicateEvents' => array(),
					'updateDatabase' => array(),
					'upgrade2324' => array(),
			),
			'attributes' => array(
					'add' => array('perm_add'),
					'add_attachment' => array('perm_add'),
					'add_threatconnect' => array('perm_add'),
					'attributeReplace' => array('perm_add'),
					'checkComposites' => array('perm_admin'),
					'delete' => array('perm_add'),
					'deleteSelected' => array('perm_add'),
					'describeTypes' => array('perm_auth'),
					'download' => array('*'),
					'downloadAttachment' => array('*'),
					'downloadSample' => array('*'),
					'edit' => array('perm_add'),
					'editField' => array('perm_add'),
					'editSelected' => array('perm_add'),
					'fetchEditForm' => array('perm_add'),
					'fetchViewValue' => array('*'),
					'generateCorrelation' => array(),
					'hoverEnrichment' => array('perm_add'),
					'index' => array('*'),
					'pruneOrphanedAttributes' => array(),
					'reportValidationIssuesAttributes' => array(),
					'restSearch' => array('*'),
					'returnAttributes' => array('*'),
					'rpz' => array('*'),
					'search' => array('*'),
					'searchAlternate' => array('*'),
					'text' => array('*'),
					'updateAttributeValues' => array('perm_add'),
					'view' => array('*'),
			),
			'eventBlacklists' => array(
					'add' => array(),
					'delete' => array(),
					'edit' => array(),
					'index' => array(),
			),
			'eventDelegations' => array(
					'acceptDelegation' => array('perm_add'),
					'delegateEvent' => array('perm_add'),
					'deleteDelegation' => array('perm_add'),
					'view' => array('*'),
			),
			'events' => array(
					'add' => array('perm_add'),
					'addIOC' => array('perm_add'),
					'addTag' => array('perm_tagger'),
					'add_misp_export' => array('perm_modify'),
					'alert' => array('perm_publish'),
					'automation' => array('perm_auth'),
					'checkuuid' => array('perm_sync'),
					'contact' => array('*'),
					'create_dummy_event' => array(),
					'create_massive_dummy_events' => array(),
					'csv' => array('*'),
					'delegation_index' => array('*'),
					'delete' => array('perm_add'),
					'dot' => array(),
					'downloadExport' => array('*'),
					'downloadOpenIOCEvent' => array('*'),
					'downloadSearchResult' => array('*'),
					'edit' => array('perm_add'),
					'export' => array('*'),
					'exportChoice' => array('*'),
					'filterEventIdsForPush' => array('perm_sync'),
					'filterEventIndex' => array('*'),
					'freeTextImport' => array('perm_add'),
					'hids' => array('*'),
					'index' => array('*'),
					'nids' => array('*'),
					'proposalEventIndex' => array('*'),
					'publish' => array('perm_publish'),
					'pushProposals' => array('perm_sync'),
					'queryEnrichment' => array('perm_add'),
					'removePivot' => array('*'),
					'removeTag' => array('perm_tagger'),
					'reportValidationIssuesEvents' => array(),
					'restSearch' => array('*'),
					'saveFreeText' => array('perm_add'),
					'stix' => array('*'),
					'strposarray' => array(),
					'updateGraph' => array('*'),
					'upload_sample' => array('perm_auth'),
					'view' => array('*'),
					'viewEventAttributes' => array('*'),
					'viewGraph' => array('*'),
					'xml' => array('*'),
			),
			'feeds' => array(
					'add' => array(),
					'delete' => array(),
					'edit' => array(),
					'fetchFromFeed' => array(),
					'getEvent' => array(),
					'index' => array(),
					'previewEvent' => array(),
					'previewIndex' => array(),
					'view' => array(),
			),
			'jobs' => array(
					'cache' => array(),
					'getGenerateCorrelationProgress' => array(),
					'getProgress' => array(),
					'index' => array(),
			),
			'logs' => array(
					'admin_index' => array(),
					'admin_search' => array(),
					'event_index' => array(),
					'maxDateActivity' => array(),
					'returnDates' => array(),
			),
			'orgBlacklists' => array(
					'add' => array(),
					'delete' => array(),
					'edit' => array(),
					'index' => array(),
			),
			'organisations' => array(
					'admin_add' => array(),
					'admin_delete' => array(),
					'admin_edit' => array(),
					'admin_generateuuid' => array(),
					'admin_merge' => array(),
					'fetchOrgsForSG' => array(),
					'fetchSGOrgRow' => array(),
					'getUUIDs' => array(),
					'index' => array(),
					'landingpage' => array(),
					'view' => array(),
			),
			'pages' => array(
					'display' => array(),
			),
			'posts' => array(
					'add' => array(),
					'delete' => array(),
					'edit' => array(),
			),
			'regexp' => array(
					'admin_add' => array(),
					'admin_clean' => array(),
					'admin_delete' => array(),
					'admin_edit' => array(),
					'admin_index' => array(),
					'cleanRegexModifiers' => array(),
					'index' => array(),
			),
			'roles' => array(
					'admin_add' => array(),
					'admin_delete' => array(),
					'admin_edit' => array(),
					'admin_index' => array(),
					'index' => array(),
					'view' => array(),
			),
			'servers' => array(
					'add' => array(),
					'delete' => array(),
					'deleteFile' => array(),
					'edit' => array(),
					'fetchServersForSG' => array(),
					'filterEventIndex' => array(),
					'getVersion' => array(),
					'index' => array(),
					'previewEvent' => array(),
					'previewIndex' => array(),
					'pull' => array(),
					'purgeSessions' => array(),
					'push' => array(),
					'restartWorkers' => array(),
					'serverSettings' => array(),
					'serverSettingsEdit' => array(),
					'serverSettingsReloadSetting' => array(),
					'startWorker' => array(),
					'startZeroMQServer' => array(),
					'statusZeroMQServer' => array(),
					'stopWorker' => array(),
					'stopZeroMQServer' => array(),
					'testConnection' => array(),
					'uploadFile' => array(),
			),
			'shadowAttributes' => array(
					'accept' => array(),
					'acceptSelected' => array(),
					'add' => array(),
					'add_attachment' => array(),
					'delete' => array(),
					'discard' => array(),
					'discardSelected' => array(),
					'download' => array(),
					'edit' => array(),
					'editField' => array(),
					'fetchEditForm' => array(),
					'generateCorrelation' => array(),
					'getProposalsByUuid' => array(),
					'getProposalsByUuidList' => array(),
					'index' => array(),
					'view' => array(),
			),
			'sharingGroups' => array(
					'add' => array(),
					'delete' => array(),
					'edit' => array(),
					'index' => array(),
					'view' => array(),
			),
			'sightings' => array(
					'add' => array(),
					'delete' => array(),
			),
			'tags' => array(
					'add' => array(),
					'delete' => array(),
					'edit' => array(),
					'index' => array(),
					'quickAdd' => array(),
					'selectTag' => array(),
					'selectTaxonomy' => array(),
					'showEventTag' => array(),
					'view' => array(),
					'viewTag' => array(),
			),
			'tasks' => array(
					'index' => array(),
					'setTask' => array(),
			),
			'taxonomies' => array(
					'addTag' => array(),
					'disable' => array(),
					'enable' => array(),
					'index' => array(),
					'taxonomyMassConfirmation' => array(),
					'update' => array(),
					'view' => array(),
			),
			'templateElements' => array(
					'add' => array(),
					'delete' => array(),
					'edit' => array(),
					'index' => array(),
					'templateElementAddChoices' => array(),
			),
			'templates' => array(
					'add' => array(),
					'delete' => array(),
					'deleteTemporaryFile' => array(),
					'edit' => array(),
					'index' => array(),
					'populateEventFromTemplate' => array(),
					'saveElementSorting' => array(),
					'submitEventPopulation' => array(),
					'templateChoices' => array(),
					'uploadFile' => array(),
					'view' => array(),
			),
			'threads' => array(
					'index' => array(),
					'view' => array(),
					'viewEvent' => array(),
			),
			'users' => array(
					'admin_add' => array(),
					'admin_delete' => array(),
					'admin_edit' => array(),
					'admin_email' => array(),
					'admin_filterUserIndex' => array(),
					'admin_index' => array(),
					'admin_view' => array(),
					'arrayCopy' => array(),
					'change_pw' => array(),
					'checkAndCorrectPgps' => array(),
					'dashBoard' => array(),
					'delete' => array(),
					'downloadTerms' => array(),
					'edit' => array(),
					'fetchPGPKey' => array(),
					'histogram' => array(),
					'index' => array(),
					'initiatePasswordReset' => array(),
					'login' => array(),
					'logout' => array(),
					'memberslist' => array(),
					'resetauthkey' => array(),
					'routeafterlogin' => array(),
					'statistics' => array(),
					'terms' => array(),
					'updateLoginTime' => array(),
					'verifyGPG' => array(),
					'view' => array(),
			),
			'whitelists' => array(
					'admin_add' => array(),
					'admin_delete' => array(),
					'admin_edit' => array(),
					'admin_index' => array(),
					'index' => array(),
			)
	);
	
	public function checkAccess($user, $controller, $action) {
		if (!isset($this->__aclList[$controller])) $this->__error(404, 'Invalid controller.');
		if (isset($this->__aclList[$controller]['*']) || 
			$user['Role']['perm_site_admin'] || 
			(isset($this->__aclList[$controller][$action]) && $user['Role'][$this->__aclList[$controller][$action]])
		) return true;
		$this->__error(403, 'You do not have permission to use this functionality.');
	}
	
	private function __error($code, $message) {
		switch ($code) {
			case 404: 
				throw new NotFoundException($message);
				break;
			default:
				throw new InternalErrorException('Unknown error: ' . $message); 
		}
	}
	
	public function printAllFunctionNames() {
		$functionFinder = '/function[\s\n]+(\S+)[\s\n]*\(/';
		$dir = new Folder(APP . 'Controller');
		$files = $dir->find('.*\.php');
		$results = array();
		foreach ($files as $file) {
			$controllerName = lcfirst(str_replace('Controller.php', "", $file));
			if ($controllerName === 'app') $controllerName = '*';
			$functionArray = array();
			$fileContents = file_get_contents(APP . 'Controller' . DS . $file);
			preg_match_all($functionFinder, $fileContents, $functionArray);
			foreach ($functionArray[1] as $function) {
				if (substr($function, 0, 1) !== '_' && $function !== 'beforeFilter') $results[$controllerName][] = $function;
			}
			if( count( $functionArray )>1 ){
				$functionArray = $functionArray[1];
			}
		}
	
		$pretty = "";
		ksort($results);
		foreach ($results as $controller => $functions) {
			$pretty .= "'" . $controller . "' => array(" . PHP_EOL;
			sort($functions);
			foreach ($functions as $method) {
				$pretty .= "\t'" . $method . "' => array()," . PHP_EOL;
			}
			$pretty .= ")," . PHP_EOL;
		}
		debug($pretty);
	} 
		
	
}