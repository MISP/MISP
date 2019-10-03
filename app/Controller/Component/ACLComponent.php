<?php
App::uses('Component', 'Controller');

class ACLComponent extends Component
{

    // syntax:
    // $__aclList[$controller][$action] = $permission_rules
    // $controller == '*'                 -  any controller can have this action
    // $action == array()                 -  site admin only has access
    // $action == '*'                     -  any role has access
    // $action == array('OR' => array())  -  any role in the array has access
    // $action == array('AND' => array()) -  roles with all permissions in the array have access
    // If we add any new functionality to MISP and we don't add it to this list, it will only be visible to site admins.
    private $__aclList = array(
            '*' => array(
                    'blackhole' => array(),
                    'checkAction' => array(),
                    'checkAuthUser' => array(),
                    'checkExternalAuthUser' => array(),
                    'cleanModelCaches' => array(),
                    'debugACL' => array(),
                    'generateCount' => array(),
                    'getActions' => array(),
                    'pruneDuplicateUUIDs' => array(),
                    'queryACL' => array(),
                    'removeDuplicateEvents' => array(),
                    'updateDatabase' => array(),
                    'upgrade2324' => array(),
            ),
            'attributes' => array(
                    'add' => array('perm_add'),
                    'add_attachment' => array('perm_add'),
                    'add_threatconnect' => array('perm_add'),
                    'addTag' => array('perm_tagger'),
                    'attributeReplace' => array('perm_add'),
                    'attributeStatistics' => array('*'),
                    'bro' => array('*'),
                    'checkAttachments' => array(),
                    'checkComposites' => array('perm_admin'),
                    'checkOrphanedAttributes' => array(),
                    'delete' => array('perm_add'),
                    'deleteSelected' => array('perm_add'),
                    'describeTypes' => array('*'),
                    'download' => array('*'),
                    'downloadAttachment' => array('*'),
                    'downloadSample' => array('*'),
                    'edit' => array('perm_add'),
                    'editField' => array('perm_add'),
                    'editSelected' => array('perm_add'),
                    'exportSearch' => array('*'),
                    'fetchEditForm' => array('perm_add'),
                    'fetchViewValue' => array('*'),
                    'generateCorrelation' => array(),
                    'hoverEnrichment' => array('perm_add'),
                    'index' => array('*'),
                    'pruneOrphanedAttributes' => array(),
                    'removeTag' => array('perm_tagger'),
                    'reportValidationIssuesAttributes' => array(),
                    'restore' => array('perm_add'),
                    'restSearch' => array('*'),
                    'returnAttributes' => array('*'),
                    'rpz' => array('*'),
                    'search' => array('*'),
                    'searchAlternate' => array('*'),
                    'toggleCorrelation' => array('perm_add'),
                    'text' => array('*'),
                    'toggleToIDS' => array('perm_add'),
                    'updateAttributeValues' => array('perm_add'),
                    'view' => array('*'),
                    'viewPicture' => array('*'),
            ),
            'decayingModel' => array(
                "update" => array(),
                "export" => array('*'),
                "import" => array('*'),
                "view" => array('*'),
                "index" => array('*'),
                "add" => array( 'OR' => array('perm_admin', 'perm_decaying')),
                "edit" => array( 'OR' => array('perm_admin', 'perm_decaying')),
                "delete" => array( 'OR' => array('perm_admin', 'perm_decaying')),
                "enable" => array( 'OR' => array('perm_admin', 'perm_decaying')),
                "disable" => array( 'OR' => array('perm_admin', 'perm_decaying')),
                "decayingTool" => array( 'OR' => array('perm_admin', 'perm_decaying')),
                "getAllDecayingModels" => array('*'),
                "decayingToolBasescore" => array('*'),
                "decayingToolSimulation" => array('*'),
                "decayingToolRestSearch" => array('*'),
                "decayingToolComputeSimulation" => array('*')
            ),
            'decayingModelMapping' => array(
                "viewAssociatedTypes" => array('*'),
                "linkAttributeTypeToModel" => array( 'OR' => array('perm_admin', 'perm_decaying'))
            ),
            'communities' => array(
                    'index' => array(),
                    'requestAccess' => array(),
                    'view' => array()
            ),
            'eventBlacklists' => array(
                    'add' => array(),
                    'delete' => array(),
                    'edit' => array(),
                    'index' => array(),
                    'massDelete' => array()
            ),
            'eventDelegations' => array(
                    'acceptDelegation' => array('perm_add'),
                    'delegateEvent' => array('perm_delegate'),
                    'deleteDelegation' => array('perm_add'),
                    'index' => array('*'),
                    'view' => array('*'),
            ),
            'events' => array(
                    'add' => array('perm_add'),
                    'addIOC' => array('perm_add'),
                    'addTag' => array('perm_tagger'),
                    'add_misp_export' => array('perm_modify'),
                    'alert' => array('perm_publish'),
                    'automation' => array('perm_auth'),
                    'checkLocks' => array('perm_add'),
                    'checkPublishedStatus' => array('*'),
                    'checkuuid' => array('perm_sync'),
                    'contact' => array('*'),
                    'create_dummy_event' => array(),
                    'create_massive_dummy_events' => array(),
                    'csv' => array('*'),
                    'cullEmptyEvents' => array(),
                    'delegation_index' => array('*'),
                    'delete' => array('perm_add'),
                    'deleteNode' => array('*'),
                    'dot' => array(),
                    'downloadExport' => array('*'),
                    'downloadOpenIOCEvent' => array('*'),
                    'downloadSearchResult' => array('*'),
                    'edit' => array('perm_add'),
                    'enrichEvent' => array('perm_add'),
                    'export' => array('*'),
                    'exportChoice' => array('*'),
                    'exportModule' => array('*'),
                    'filterEventIdsForPush' => array('perm_sync'),
                    'filterEventIndex' => array('*'),
                    'freeTextImport' => array('perm_add'),
                    'getEditStrategy' => array('perm_add'),
                    'getEventInfoById' => array('*'),
                    'getEventGraphReferences' => array('*'),
                    'getEventGraphTags' => array('*'),
                    'getEventGraphGeneric' => array('*'),
                    'genDistributionGraph' => array('*'),
                    'getDistributionGraph' => array('*'),
                    'getReferenceData' => array('*'),
                    'getReferences' => array('*'),
                    'getObjectTemplate' => array('*'),
                    'handleModuleResults' => array('*'),
                    'hids' => array('*'),
                    'index' => array('*'),
                    'importChoice' => array('*'),
                    'importModule' => array('*'),
                    'massDelete' => array('perm_site_admin'),
                    'merge' => array('perm_modify'),
                    'nids' => array('*'),
                    'proposalEventIndex' => array('*'),
                    'publish' => array('perm_publish'),
                    'pushEventToZMQ' => array('perm_publish_zmq'),
                    'pushEventToKafka' => array('perm_publish_kafka'),
                    'pushProposals' => array('perm_sync'),
                    'queryEnrichment' => array('perm_add'),
                    'removePivot' => array('*'),
                    'removeTag' => array('perm_tagger'),
                    'reportValidationIssuesEvents' => array(),
                    'restSearch' => array('*'),
                    'saveFreeText' => array('perm_add'),
                    'stix' => array('*'),
                    'stix2' => array('*'),
                    'strposarray' => array(),
                    'toggleCorrelation' => array('perm_add'),
                    'unpublish' => array('perm_modify'),
                    'updateGraph' => array('*'),
                    'upload_analysis_file' => array('perm_add'),
                    'upload_sample' => array('AND' => array('perm_auth', 'perm_add')),
                    'upload_stix' => array('perm_add'),
                    'view' => array('*'),
                    'viewEventAttributes' => array('*'),
                    'viewEventGraph' => array('*'),
                    'viewGraph' => array('*'),
                    'viewGalaxyMatrix' => array('*'),
                    'xml' => array('*')
            ),
            'favouriteTags' => array(
                'toggle' => array('*'),
                'getToggleField' => array('*')
            ),
            'feeds' => array(
                    'add' => array(),
                    'cacheFeeds' => array(),
                    'compareFeeds' => array('*'),
                    'delete' => array(),
                    'disable' => array(),
                    'edit' => array(),
                    'enable' => array(),
                    'feedCoverage' => array('*'),
                    'fetchFromAllFeeds' => array(),
                    'fetchFromFeed' => array(),
                    'fetchSelectedFromFreetextIndex' => array(),
                    'getEvent' => array(),
                    'importFeeds' => array(),
                    'index' => array('*'),
                    'previewEvent' => array('*'),
                    'previewIndex' => array('*'),
                    'searchCaches' => array('*'),
                    'toggleSelected' => array('perm_site_admin'),
                    'view' => array('*'),
            ),
            'galaxies' => array(
                'attachCluster' => array('perm_tagger'),
                'attachMultipleClusters' => array('perm_tagger'),
                'delete' => array(),
                'index' => array('*'),
                'selectGalaxy' => array('perm_tagger'),
                'selectGalaxyNamespace' => array('perm_tagger'),
                'selectCluster' => array('perm_tagger'),
                'showGalaxies' => array('*'),
                'update' => array(),
                'view' => array('*'),
                'viewGraph' => array('*')
            ),
            'galaxyClusters' => array(
                'attachToEvent' => array('perm_tagger'),
                'delete' => array('perm_site_admin'),
                'detach' => array('perm_tagger'),
                'index' => array('*'),
                'view' => array('*'),
                'viewGalaxyMatrix' => array('*')
            ),
            'galaxyElements' => array(
                    'index' => array('*')
            ),
            'jobs' => array(
                    'cache' => array('*'),
                    'getError' => array(),
                    'getGenerateCorrelationProgress' => array('*'),
                    'getProgress' => array('*'),
                    'index' => array(),
                    'clearJobs' => array()
            ),
            'logs' => array(
                    'admin_index' => array('perm_audit'),
                    'admin_search' => array('perm_audit'),
                    'event_index' => array('*'),
                    'maxDateActivity' => array('*'),
                    'returnDates' => array('*'),
                    'testForStolenAttributes' => array(),
                    'pruneUpdateLogs' => array()
            ),
      'modules' => array(
        'index' => array('perm_auth'),
        'queryEnrichment' => array('perm_auth'),
      ),
            'news' => array(
                    'add' => array(),
                    'edit' => array(),
                    'delete' => array(),
                    'index' => array('*'),
            ),
            'noticelists' => array(
                    'delete' => array(),
                    'enableNoticelist' => array(),
                    'getToggleField' => array(),
                    'index' => array('*'),
                    'toggleEnable' => array(),
                    'update' => array(),
                    'view' => array('*')
            ),
            'objects' => array(
                'add' => array('perm_add'),
                'addValueField' => array('perm_add'),
                'delete' => array('perm_add'),
                'edit' => array('perm_add'),
                'get_row' => array('perm_add'),
                'orphanedObjectDiagnostics' => array(),
                'proposeObjectsFromAttributes' => array('*'),
                'groupAttributesIntoObject' => array('perm_add'),
                'revise_object' => array('perm_add'),
                'view' => array('*'),
            ),
            'objectReferences' => array(
                'add' => array('perm_add'),
                'delete' => array('perm_add'),
                'view' => array('*'),
            ),
            'objectTemplates' => array(
                'activate' => array(),
                'add' => array('perm_object_template'),
                'edit' => array('perm_object_template'),
                'delete' => array('perm_object_template'),
                'getToggleField' => array(),
                'objectChoice' => array('*'),
                'objectMetaChoice' => array('perm_add'),
                'view' => array('*'),
                'viewElements' => array('*'),
                'index' => array('*'),
                'update' => array('perm_site_admin')
            ),
            'objectTemplateElements' => array(
                'viewElements' => array('*')
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
                    'fetchOrgsForSG' => array('*'),
                    'fetchSGOrgRow' => array('*'),
                    'getUUIDs' => array('perm_sync'),
                    'index' => array('*'),
                    'landingpage' => array('*'),
                    'view' => array('*'),
            ),
            'pages' => array(
                    'display' => array('*'),
            ),
            'posts' => array(
                    'add' => array('*'),
                    'delete' => array('*'),
                    'edit' => array('*'),
                    'pushMessageToZMQ' => array('perm_site_admin')
            ),
            'regexp' => array(
                    'admin_add' => array('perm_regexp_access'),
                    'admin_clean' => array('perm_regexp_access'),
                    'admin_delete' => array('perm_regexp_access'),
                    'admin_edit' => array('perm_regexp_access'),
                    'admin_index' => array('perm_regexp_access'),
                    'cleanRegexModifiers' => array('perm_regexp_access'),
                    'index' => array('*'),
            ),
            'restClientHistory' => array(
                    'delete' => array('*'),
                    'index' => array('*')
            ),
            'roles' => array(
                    'admin_add' => array(),
                    'admin_delete' => array(),
                    'admin_edit' => array(),
                    'admin_index' => array('perm_admin'),
                    'admin_set_default' => array(),
                    'index' => array('*'),
                    'view' => array('*'),
            ),
            'servers' => array(
                    'add' => array(),
                    'cache' => array(),
                    'changePriority' => array(),
                    'checkout' => array(),
                    'createSync' => array('perm_sync'),
                    'delete' => array(),
                    'deleteFile' => array(),
                    'edit' => array(),
                    'fetchServersForSG' => array('*'),
                    'filterEventIndex' => array(),
                    'getApiInfo' => array('*'),
                    'getGit' => array(),
                    'getInstanceUUID' => array('perm_sync'),
                    'getPyMISPVersion' => array('*'),
                    'getSetting' => array(),
                    'getSubmodulesStatus' => array(),
                    'getSubmoduleQuickUpdateForm' => array(),
                    'getWorkers' => array(),
                    'getVersion' => array('*'),
                    'import' => array(),
                    'index' => array(),
                    'ondemandAction' => array(),
                    'postTest' => array('perm_sync'),
                    'previewEvent' => array(),
                    'previewIndex' => array(),
                    'pull' => array(),
                    'purgeSessions' => array(),
                    'push' => array(),
                    'resetRemoteAuthKey' => array(),
                    'rest' => array('perm_auth'),
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
                    'update' => array(),
                    'updateJSON' => array(),
                    'updateProgress' => array(),
                    'updateSubmodule' => array(),
                    'uploadFile' => array(),
                    'clearWorkerQueue' => array()
            ),
            'shadowAttributes' => array(
                    'accept' => array('perm_add'),
                    'acceptSelected' => array('perm_add'),
                    'add' => array('perm_add'),
                    'add_attachment' => array('perm_add'),
                    'delete' => array('perm_add'),
                    'discard' => array('perm_add'),
                    'discardSelected' => array('perm_add'),
                    'download' => array('*'),
                    'edit' => array('perm_add'),
                    'editField' => array('perm_add'),
                    'fetchEditForm' => array('perm_add'),
                    'generateCorrelation' => array(),
                    'getProposalsByUuid' => array('perm_sync'),
                    'getProposalsByUuidList' => array('perm_sync'),
                    'index' => array('*'),
                    'view' => array('*'),
            ),
            'sharingGroups' => array(
                    'add' => array('perm_sharing_group'),
                    'addServer' => array('perm_sharing_group'),
                    'addOrg' => array('perm_sharing_group'),
                    'delete' => array('perm_sharing_group'),
                    'edit' => array('perm_sharing_group'),
                    'index' => array('*'),
                    'removeServer' => array('perm_sharing_group'),
                    'removeOrg' => array('perm_sharing_group'),
                    'view' => array('*'),
            ),
            'sightings' => array(
                    'add' => array('perm_sighting'),
                    'restSearch' => array('perm_sighting'),
                    'advanced' => array('perm_sighting'),
                    'delete' => array('perm_sighting'),
                    'index' => array('*'),
                    'listSightings' => array('*'),
                    'quickDelete' => array('perm_sighting'),
                    'viewSightings' => array('*'),
                    'quickAdd' => array('perm_sighting')
            ),
            'tagCollections' => array(
                    'add' => array('perm_tag_editor'),
                    'addTag' => array('perm_tag_editor'),
                    'delete' => array('perm_tag_editor'),
                    'edit' => array('perm_tag_editor'),
                    'getRow' => array('perm_tag_editor'),
                    'import' => array('perm_tag_editor'),
                    'index' => array('*'),
                    'removeTag' => array('perm_tag_editor'),
                    'view' => array('*')
            ),
            'tags' => array(
                    'add' => array('perm_tag_editor'),
                    'attachTagToObject' => array('perm_tagger'),
                    'delete' => array(),
                    'edit' => array(),
                    'index' => array('*'),
                    'quickAdd' => array('perm_tag_editor'),
                    'removeTagFromObject' => array('perm_tagger'),
                    'search' => array('*'),
                    'selectTag' => array('perm_tagger'),
                    'selectTaxonomy' => array('perm_tagger'),
                    'showEventTag' => array('*'),
                    'showAttributeTag' => array('*'),
                    'showTagControllerTag' => array('*'),
                    'tagStatistics' => array('*'),
                    'view' => array('*'),
                    'viewGraph' => array('*'),
                    'viewTag' => array('*')
            ),
            'tasks' => array(
                    'index' => array(),
                    'setTask' => array(),
            ),
            'taxonomies' => array(
                    'addTag' => array(),
                    'delete' => array(),
                    'disable' => array(),
                    'disableTag' => array(),
                    'enable' => array(),
                    'index' => array('*'),
                    'taxonomyMassConfirmation' => array('perm_tagger'),
                    'taxonomyMassHide' => array('perm_tagger'),
                    'taxonomyMassUnhide' => array('perm_tagger'),
                    'toggleRequired' => array('perm_site_admin'),
                    'update' => array(),
                    'view' => array('*'),
                    'unhideTag' => array('perm_tagger'),
                    'hideTag' => array('perm_tagger'),
            ),
            'templateElements' => array(
                    'add' => array('perm_template'),
                    'delete' => array('perm_template'),
                    'edit' => array('perm_template'),
                    'index' => array('*'),
                    'templateElementAddChoices' => array('perm_template'),
            ),
            'templates' => array(
                    'add' => array('perm_template'),
                    'delete' => array('perm_template'),
                    'deleteTemporaryFile' => array('perm_add'),
                    'edit' => array('perm_template'),
                    'index' => array('*'),
                    'populateEventFromTemplate' => array('perm_add'),
                    'saveElementSorting' => array('perm_template'),
                    'submitEventPopulation' => array('perm_add'),
                    'templateChoices' => array('*'),
                    'uploadFile' => array('*'),
                    'view' => array('*'),
            ),
            'threads' => array(
                    'index' => array('*'),
                    'view' => array('*'),
                    'viewEvent' => array('*'),
            ),
            'users' => array(
                    'admin_add' => array('perm_admin'),
                    'admin_delete' => array('perm_admin'),
                    'admin_edit' => array('perm_admin'),
                    'admin_email' => array('perm_admin'),
                    'admin_filterUserIndex' => array('perm_admin'),
                    'admin_index' => array('perm_admin'),
                    'admin_quickEmail' => array('perm_admin'),
                    'admin_view' => array('perm_admin'),
                    'attributehistogram' => array('*'),
                    'change_pw' => array('*'),
                    'checkAndCorrectPgps' => array(),
                    'checkIfLoggedIn' => array('*'),
                    'dashboard' => array('*'),
                    'delete' => array('perm_admin'),
                    'downloadTerms' => array('*'),
                    'edit' => array('*'),
                    'fetchPGPKey' => array('*'),
                    'histogram' => array('*'),
                    'initiatePasswordReset' => array('perm_admin'),
                    'login' => array('*'),
                    'logout' => array('*'),
                    'resetAllSyncAuthKeys' => array(),
                    'resetauthkey' => array('*'),
                    'request_API' => array('*'),
                    'routeafterlogin' => array('*'),
                    'statistics' => array('*'),
                    'tagStatisticsGraph' => array('*'),
                    'terms' => array('*'),
                    'updateLoginTime' => array('*'),
                    'verifyCertificate' => array(),
                    'verifyGPG' => array(),
                    'view' => array('*'),
            ),
            'userSettings' => array(
                    'index' => array('*'),
                    'view' => array('*'),
                    'setSetting' => array('*'),
                    'getSetting' => array('*'),
                    'delete' => array('*')
            ),
            'warninglists' => array(
                    'checkValue' => array('perm_auth'),
                    'delete' => array(),
                    'enableWarninglist' => array(),
                    'getToggleField' => array(),
                    'index' => array('*'),
                    'toggleEnable' => array(),
                    'update' => array(),
                    'view' => array('*')
            ),
            'whitelists' => array(
                    'admin_add' => array('perm_regexp_access'),
                    'admin_delete' => array('perm_regexp_access'),
                    'admin_edit' => array('perm_regexp_access'),
                    'admin_index' => array('perm_regexp_access'),
                    'index' => array('*'),
            ),
            'eventGraph' => array(
                    'view' => array('*'),
                    'add' => array('perm_add'),
                    'delete' => array('perm_modify'),
            )
    );

    private function __checkLoggedActions($user, $controller, $action)
    {
        $loggedActions = array(
            'servers' => array(
                'index' => array(
                    'role' => array(
                        'NOT' => array(
                            'perm_site_admin'
                        )
                    ),
                    'message' => __('This could be an indication of an attempted privilege escalation on older vulnerable versions of MISP (<2.4.115)')
                )
            )
        );
        foreach ($loggedActions as $k => $v) {
            $loggedActions[$k] = array_change_key_case($v);
        }
        $message = '';
        if (!empty($loggedActions[$controller])) {
            if (!empty($loggedActions[$controller][$action])) {
                $message = $loggedActions[$controller][$action]['message'];
                $hit = false;
                if (empty($loggedActions[$controller][$action]['role'])) {
                    $hit = true;
                } else {
                    $role_req = $loggedActions[$controller][$action]['role'];
                    if (empty($role_req['OR']) && empty($role_req['AND']) && empty($role_req['NOT'])) {
                        $role_req = array('OR' => $role_req);
                    }
                    if (!empty($role_req['NOT'])) {
                        foreach ($role_req['NOT'] as $k => $v) {
                            if (!$user['Role'][$v]) {
                                $hit = true;
                                continue;
                            }
                        }
                    }
                    if (!$hit && !empty($role_req['AND'])) {
                        $subhit = true;
                        foreach ($role_req['AND'] as $k => $v) {
                            $subhit = $subhit && $user['Role'][$v];
                        }
                        if ($subhit) {
                            $hit = true;
                        }
                    }
                    if (!$hit && !empty($role_req['OR'])) {
                        foreach ($role_req['OR'] as $k => $v) {
                            if ($user['Role'][$v]) {
                                $hit = true;
                                continue;
                            }
                        }
                    }
                    if ($hit) {
                        $this->Log = ClassRegistry::init('Log');
                        $this->Log->create();
                        $this->Log->save(array(
                                'org' => 'SYSTEM',
                                'model' => 'User',
                                'model_id' => $user['id'],
                                'email' => $user['email'],
                                'action' => 'security',
                                'user_id' => $user['id'],
                                'title' => __('User triggered security alert by attempting to access /%s/%s. Reason why this endpoint is of interest: %s', $controller, $action, $message),
                        ));
                    }
                }
            }
        }
    }

    // The check works like this:
    // If the user is a site admin, return true
    // If the requested action has an OR-d list, iterate through the list. If any of the permissions are set for the user, return true
    // If the requested action has an AND-ed list, iterate through the list. If any of the permissions for the user are not set, turn the check to false. Otherwise return true.
    // If the requested action has a permission, check if the user's role has it flagged. If yes, return true
    // If we fall through all of the checks, return an exception.
    public function checkAccess($user, $controller, $action, $soft = false)
    {
        $controller = lcfirst(Inflector::camelize($controller));
        $action = strtolower($action);
        $aclList = $this->__aclList;
        foreach ($aclList as $k => $v) {
            $aclList[$k] = array_change_key_case($v);
        }
        $this->__checkLoggedActions($user, $controller, $action);
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (!isset($aclList[$controller])) {
            return $this->__error(404, 'Invalid controller.', $soft);
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (isset($aclList[$controller][$action]) && !empty($aclList[$controller][$action])) {
            if (in_array('*', $aclList[$controller][$action])) {
                return true;
            }
            if (isset($aclList[$controller][$action]['OR'])) {
                foreach ($aclList[$controller][$action]['OR'] as $permission) {
                    if ($user['Role'][$permission]) {
                        return true;
                    }
                }
            } elseif (isset($aclList[$controller][$action]['AND'])) {
                $allConditionsMet = true;
                foreach ($aclList[$controller][$action]['AND'] as $permission) {
                    if (!$user['Role'][$permission]) {
                        $allConditionsMet = false;
                    }
                }
                if ($allConditionsMet) {
                    return true;
                }
            } elseif ($user['Role'][$aclList[$controller][$action][0]]) {
                return true;
            }
        }
        return $this->__error(403, 'You do not have permission to use this functionality.', $soft);
    }

    private function __error($code, $message, $soft = false)
    {
        if ($soft) {
            return $code;
        }
        switch ($code) {
            case 404:
                throw new NotFoundException($message);
                break;
            case 403:
                throw new MethodNotAllowedException($message);
            default:
                throw new InternalErrorException('Unknown error: ' . $message);
        }
    }

    private function __findAllFunctions()
    {
        $functionFinder = '/function[\s\n]+(\S+)[\s\n]*\(/';
        $dir = new Folder(APP . 'Controller');
        $files = $dir->find('.*\.php');
        $results = array();
        foreach ($files as $file) {
            $controllerName = lcfirst(str_replace('Controller.php', "", $file));
            if ($controllerName === 'app') {
                $controllerName = '*';
            }
            $functionArray = array();
            $fileContents = file_get_contents(APP . 'Controller' . DS . $file);
            $fileContents = preg_replace('/\/\*[^\*]+?\*\//', '', $fileContents);
            preg_match_all($functionFinder, $fileContents, $functionArray);
            foreach ($functionArray[1] as $function) {
                if (substr($function, 0, 1) !== '_' && $function !== 'beforeFilter' && $function !== 'afterFilter') {
                    $results[$controllerName][] = $function;
                }
            }
        }
        return $results;
    }

    public function printAllFunctionNames($content = false)
    {
        $results = $this->__findAllFunctions();
        ksort($results);
        return $results;
    }

    public function findMissingFunctionNames($content = false)
    {
        $results = $this->__findAllFunctions();
        $missing = array();
        foreach ($results as $controller => $functions) {
            foreach ($functions as $function) {
                if (!isset($this->__aclList[$controller])
                || !in_array($function, array_keys($this->__aclList[$controller]))) {
                    $missing[$controller][] = $function;
                }
            }
        }
        return $missing;
    }

    public function printRoleAccess($content = false)
    {
        $results = array();
        $this->Role = ClassRegistry::init('Role');
        $conditions = array();
        if (is_numeric($content)) {
            $conditions = array('Role.id' => $content);
        }
        $roles = $this->Role->find('all', array(
            'recursive' => -1,
            'conditions' => $conditions
        ));
        if (empty($roles)) {
            throw new NotFoundException('Role not found.');
        }
        foreach ($roles as $role) {
            $urls = $this->__checkRoleAccess($role['Role']);
            $results[$role['Role']['id']] = array('name' => $role['Role']['name'], 'urls' => $urls);
        }
        return $results;
    }

    private function __checkRoleAccess($role)
    {
        $result = array();
        foreach ($this->__aclList as $controller => $actions) {
            $controllerNames = Inflector::variable($controller) == Inflector::underscore($controller) ? array(Inflector::variable($controller)) : array(Inflector::variable($controller), Inflector::underscore($controller));
            foreach ($controllerNames as $controllerName) {
                foreach ($actions as $action => $permissions) {
                    if ($role['perm_site_admin']) {
                        $result[] = DS . $controllerName . DS . $action;
                    } elseif (in_array('*', $permissions)) {
                        $result[] = DS . $controllerName . DS . $action . DS . '*';
                    } elseif (isset($permissions['OR'])) {
                        $access = false;
                        foreach ($permissions['OR'] as $permission) {
                            if ($role[$permission]) {
                                $access = true;
                            }
                        }
                        if ($access) {
                            $result[] = DS . $controllerName . DS . $action . DS . '*';
                        }
                    } elseif (isset($permissions['AND'])) {
                        $access = true;
                        foreach ($permissions['AND'] as $permission) {
                            if ($role[$permission]) {
                                $access = false;
                            }
                        }
                        if ($access) {
                            $result[] = DS . $controllerName . DS . $action . DS . '*';
                        }
                    } elseif (isset($permissions[0]) && $role[$permissions[0]]) {
                        $result[] = DS . $controllerName . DS . $action . DS . '*';
                    }
                }
            }
        }
        return $result;
    }
}
