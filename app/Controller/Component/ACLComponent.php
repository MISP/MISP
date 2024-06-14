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
    const ACL_LIST = array(
        '*' => array(
            'blackhole' => array(),
            'debugACL' => array(),
            'queryACL' => array(),
            'restSearch' => array('*'),
        ),
        'analystData' => [
            'add' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'delete' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'edit' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'filterAnalystDataForPush' => ['perm_sync'],
            'getChildren' => ['*'],
            'getRelatedElement' => ['*'],
            'index' => ['*'],
            'indexMinimal' => ['*'],
            'pushAnalystData' => ['perm_sync'],
            'view' => ['*'],
        ],
        'analystDataBlocklists' => array(
            'add' => array(),
            'delete' => array(),
            'edit' => array(),
            'index' => array(),
            'massDelete' => array(),
        ),
        'api' => [
            'rest' => ['perm_auth'],
            'viewDeprecatedFunctionUse' => [],
            'openapi' => ['*'],
            'getApiInfo' => ['*'],
            'getAllApis' => ['*'],
        ],
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
            'enrich' => ['perm_add'],
            'exportSearch' => array('*'),
            'fetchEditForm' => array('perm_add'),
            'fetchViewValue' => array('*'),
            'generateCorrelation' => array(),
            'getMassEditForm' => array('perm_add'),
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
            'toggleCorrelation' => array('perm_add'),
            'text' => array('*'),
            'toggleToIDS' => array('perm_add'),
            'updateAttributeValues' => array('perm_add'),
            'view' => array('*'),
            'viewAnalystData' => ['*'],
            'viewPicture' => array('*'),
        ),
        'authKeys' => [
            'add' => ['AND' => ['perm_auth', 'not_read_only_authkey']],
            'delete' => ['AND' => ['perm_auth', 'not_read_only_authkey']],
            'edit' => ['AND' => ['perm_auth', 'not_read_only_authkey']],
            'pin' => ['AND' => ['perm_auth', 'not_read_only_authkey']],
            'index' => ['perm_auth'],
            'view' => ['perm_auth'],
        ],
        'benchmarks' => [
            'index' => []
        ],
        'cerebrates' => [
            'add' => [],
            'delete' => [],
            'download_org' => [],
            'download_sg' => [],
            'edit' => [],
            'index' => [],
            'preview_orgs' => [],
            'preview_sharing_groups' => [],
            'pull_orgs' => [],
            'pull_sgs' => [],
            'view' => []
        ],
        'collections' => [
            'add' => ['perm_modify'],
            'delete' => ['perm_modify'],
            'edit' => ['perm_modify'],
            'index' => ['*'],
            'view' => ['*']
        ],
        'collectionElements' => [
            'add' => ['perm_modify'],
            'addElementToCollection' => ['perm_modify'],
            'delete' => ['perm_modify'],
            'index' => ['*']
        ],
        'correlationExclusions' => [
            'add' => [],
            'edit' => [],
            'clean' => [],
            'delete' => [],
            'index' => [],
            'view' => []
        ],
        'correlations' => [
            'generateOccurrences' => [],
            'generateTopCorrelations' => [],
            'overCorrelations' => [],
            'switchEngine' => [],
            'top' => [],
            'truncate' => []
        ],
        'cryptographicKeys' => [
            'add' => ['perm_add'],
            'delete' => ['perm_add'],
            'index' => ['*'],
            'view' => ['*']
        ],
        'dashboards' => array(
            'getForm' => array('*'),
            'index' => array('*'),
            'updateSettings' => array('*'),
            'getEmptyWidget' => array('*'),
            'renderWidget' => array('*'),
            'listTemplates' => array('*'),
            'saveTemplate' => array('*'),
            'export' => array('*'),
            'import' => array('*'),
            'deleteTemplate' => array('*')
        ),
        'decayingModel' => array(
            "update" => array(),
            "export" => array('*'),
            "import" => array('OR' => array('perm_admin', 'perm_decaying')),
            "view" => array('*'),
            "index" => array('*'),
            "add" => array('OR' => array('perm_admin', 'perm_decaying')),
            "edit" => array('OR' => array('perm_admin', 'perm_decaying')),
            "delete" => array('OR' => array('perm_admin', 'perm_decaying')),
            "enable" => array('OR' => array('perm_admin', 'perm_decaying')),
            "disable" => array('OR' => array('perm_admin', 'perm_decaying')),
            "decayingTool" => array('OR' => array('perm_admin', 'perm_decaying')),
            "getAllDecayingModels" => array('*'),
            "decayingToolBasescore" => array('*'),
            "decayingToolSimulation" => array('*'),
            "decayingToolRestSearch" => array('*'),
            "decayingToolComputeSimulation" => array('*')
        ),
        'decayingModelMapping' => array(
            "viewAssociatedTypes" => array('*'),
            "linkAttributeTypeToModel" => array('OR' => array('perm_admin', 'perm_decaying'))
        ),
        'communities' => array(
            'index' => array(),
            'requestAccess' => array(),
            'view' => array()
        ),
        'eventBlocklists' => array(
            'add' => [
                'AND' => [
                    'host_org_user',
                    'perm_add'
                ]
            ],
            'delete' => [
                'AND' => [
                    'host_org_user',
                    'perm_add'
                ]
            ],
            'edit' => [
                'AND' => [
                    'host_org_user',
                    'perm_add'
                ]
            ],
            'index' => [
                'AND' => [
                    'host_org_user',
                    'perm_add'
                ]
            ],
            'massDelete' => [
                'AND' => [
                    'host_org_user',
                    'perm_add'
                ]
            ]
        ),
        'eventDelegations' => array(
            'acceptDelegation' => array('AND' => ['delegation_enabled', 'perm_add']),
            'delegateEvent' => array('AND' => ['delegation_enabled', 'perm_delegate']),
            'deleteDelegation' => array('AND' => ['delegation_enabled', 'perm_add']),
            'index' => array('delegation_enabled'),
            'view' => array('delegation_enabled'),
        ),
        'eventReports' => array(
            'add' => array('perm_add'),
            'view' => array('*'),
            'viewSummary' => array('*'),
            'edit' => array('perm_add'),
            'delete' => array('perm_add'),
            'reportFromEvent' => array('perm_add'),
            'restore' => array('perm_add'),
            'index' => array('*'),
            'getProxyMISPElements' => array('*'),
            'extractAllFromReport' => array('*'),
            'extractFromReport' => array('*'),
            'replaceSuggestionInReport' => array('*'),
            'importReportFromUrl' => array('*'),
            'sendToLLM' => ['*'],
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
            'csv' => array('*'),
            'cullEmptyEvents' => array(),
            'delegation_index' => array('*'),
            'delete' => array('perm_add'),
            'deleteNode' => array('*'),
            'dot' => array(),
            'downloadExport' => array('*'),
            'downloadOpenIOCEvent' => array('*'),
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
            'getEventTimeline' => array('*'),
            'getDistributionGraph' => array('*'),
            'getReferenceData' => array('*'),
            'getReferences' => array('*'),
            'getObjectTemplate' => array('*'),
            'handleModuleResults' => array('*'),
            'hids' => array('*'),
            'index' => array('*'),
            'importChoice' => array('*'),
            'importModule' => array('*'),
            'massDelete' => array(),
            'merge' => array('perm_modify'),
            'nids' => array('*'),
            'populate' => array('perm_add'),
            'proposalEventIndex' => array('*'),
            'protect' => ['perm_add'],
            'publish' => array('perm_publish'),
            'publishSightings' => array('perm_sighting'),
            'pushEventToZMQ' => array('perm_publish_zmq'),
            'pushEventToKafka' => array('perm_publish_kafka'),
            'pushProposals' => array('perm_sync'),
            'queryEnrichment' => array('perm_add'),
            'recoverEvent' => array(),
            'removePivot' => array('*'),
            'removeTag' => array('perm_tagger'),
            'reportValidationIssuesEvents' => array(),
            'restoreDeletedEvents' => array(),
            'restSearch' => array('*'),
            'restSearchExport' => array('*'),
            'runTaxonomyExclusivityCheck' => array('*'),
            'saveFreeText' => array('perm_add'),
            'stix' => array('*'),
            'stix2' => array('*'),
            'strposarray' => array(),
            'toggleCorrelation' => array('perm_add'),
            'unprotect' => ['perm_add'],
            'unpublish' => array('perm_modify'),
            'updateGraph' => array('*'),
            'upload_analysis_file' => array('perm_add'),
            'upload_sample' => array('AND' => array('perm_auth', 'perm_add')),
            'upload_stix' => array('perm_modify'),
            'view' => array('*'),
            'viewClusterRelations' => array('*'),
            'viewEventAttributes' => array('*'),
            'viewGraph' => array('*'),
            'viewGalaxyMatrix' => array('*'),
            'xml' => array('*'),
            'addEventLock' => ['perm_auth'],
            'removeEventLock' => ['perm_auth'],
            'generateCount' => array(),
        ),
        'favouriteTags' => array(
            'toggle' => array('*'),
            'getToggleField' => array('*')
        ),
        'feeds' => array(
            'add' => array(),
            'cacheFeeds' => array(),
            'compareFeeds' => ['*'],
            'delete' => array(),
            'disable' => array(),
            'edit' => array(),
            'enable' => array(),
            'feedCoverage' => ['host_org_user'],
            'fetchFromAllFeeds' => array(),
            'fetchFromFeed' => array(),
            'fetchSelectedFromFreetextIndex' => array(),
            'getEvent' => array(),
            'importFeeds' => array(),
            'index' => ['*'],
            'loadDefaultFeeds' => array(),
            'previewEvent' => ['*'],
            'previewIndex' => ['*'],
            'searchCaches' => ['*'],
            'toggleSelected' => array(),
            'view' => ['host_org_user'],
        ),
        'galaxies' => array(
            'attachCluster' => array('perm_tagger'),
            'attachMultipleClusters' => array('perm_tagger'),
            'delete' => array(),
            'disable' => array(),
            'enable' => array(),
            'export' => array('*'),
            'forkTree' => array('*'),
            'index' => array('*'),
            'import' => array('perm_galaxy_editor'),
            'pushCluster' => array('perm_sync'),
            'relationsGraph' => array('*'),
            'selectGalaxy' => array('perm_tagger'),
            'selectGalaxyNamespace' => array('perm_tagger'),
            'selectCluster' => array('perm_tagger'),
            'showGalaxies' => array('*'),
            'toggle' => array(),
            'update' => array(),
            'view' => array('*'),
            'viewGraph' => array('*'),
            'wipe_default' => array(),
        ),
        'galaxyClusterBlocklists' => array(
            'add' => array(),
            'delete' => array(),
            'edit' => array(),
            'index' => array(),
            'massDelete' => array(),
        ),
        'galaxyClusters' => array(
            'add' => array('perm_galaxy_editor'),
            'delete' => array('perm_galaxy_editor'),
            'detach' => array('perm_tagger'),
            'edit' => array('perm_galaxy_editor'),
            'index' => array('*'),
            'publish' => array('perm_galaxy_editor'),
            'restore' => array('perm_galaxy_editor'),
            'restSearch' => array('*'),
            'unpublish' => array('perm_galaxy_editor'),
            'updateCluster' => array('perm_galaxy_editor'),
            'view' => array('*'),
            'viewCyCatRelations' => array('*'),
            'viewGalaxyMatrix' => array('*'),
            'viewRelations' => array('*'),
            'viewRelationTree' => array('*'),
        ),
        'galaxyClusterRelations' => array(
            'add' => array('perm_galaxy_editor'),
            'delete' => array('perm_galaxy_editor'),
            'edit' => array('perm_galaxy_editor'),
            'index' => array('*'),
            'view' => array('*'),
        ),
        'galaxyElements' => array(
            'delete' => array('perm_galaxy_editor'),
            'flattenJson' => array('perm_galaxy_editor'),
            'index' => array('*'),
        ),
        'jobs' => array(
            'cache' => array('*'),
            'getError' => array(),
            'getGenerateCorrelationProgress' => array(),
            'getProgress' => array('*'),
            'index' => array(),
            'clearJobs' => array()
        ),
        'logs' => array(
            'admin_index' => array('perm_audit'),
            'admin_search' => array('perm_audit'),
            'event_index' => array('*'),
            'returnDates' => array('*'),
            'testForStolenAttributes' => array(),
            'pruneUpdateLogs' => array(),
            'index' => array('perm_audit')
        ),
        'auditLogs' => [
            'admin_index' => ['perm_audit'],
            'fullChange' => ['perm_audit'],
            'eventIndex' => ['*'],
            'returnDates' => ['*'],
        ],
        'accessLogs' => [
            'admin_index' => [],
            'admin_request' => [],
            'admin_queryLog' => [],
        ],
        'modules' => array(
            'index' => array('perm_auth'),
            'queryEnrichment' => array('perm_auth'),
        ),
        'news' => array(
            'add' => array(),
            'edit' => array(),
            'delete' => array(),
            'admin_index' => array(),
            'index' => ['*'],
        ),
        'noticelists' => array(
            'delete' => array(),
            'enableNoticelist' => array(),
            'getToggleField' => array(),
            'index' => array('*'),
            'toggleEnable' => array(),
            'update' => array(),
            'view' => array('*'),
            'preview_entries' => array('*')
        ),
        'objects' => array(
            'add' => array('perm_add'),
            'addValueField' => array('perm_add'),
            'delete' => array('perm_add'),
            'edit' => array('perm_add'),
            'get_row' => array('perm_add'),
            'orphanedObjectDiagnostics' => array(),
            'editField' => array('perm_add'),
            'fetchEditForm' => array('perm_add'),
            'fetchViewValue' => array('*'),
            'quickAddAttributeForm' => array('perm_add'),
            'quickFetchTemplateWithValidObjectAttributes' => array('perm_add'),
            'restSearch' => array('*'),
            'proposeObjectsFromAttributes' => array('*'),
            'groupAttributesIntoObject' => array('perm_add'),
            'revise_object' => array('perm_add'),
            'view' => array('*'),
            'viewAnalystData' => ['*'],
            'createFromFreetext' => ['perm_add'],
        ),
        'objectReferences' => array(
            'add' => array('perm_add'),
            'bulkAdd' => array('perm_add'),
            'delete' => array('perm_add'),
            'view' => array('*'),
        ),
        'objectTemplates' => array(
            'activate' => array(),
            'add' => array('perm_object_template'),
            'edit' => array('perm_object_template'),
            'delete' => array('perm_object_template'),
            'getToggleField' => array(),
            'getRaw' => array('perm_object_template'),
            'objectChoice' => array('*'),
            'objectMetaChoice' => array('perm_add'),
            'view' => array('*'),
            'index' => array('*'),
            'update' => array(),
            'possibleObjectTemplates' => ['*'],
        ),
        'objectTemplateElements' => array(
            'viewElements' => array('*')
        ),
        'orgBlocklists' => array(
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
            'fetchOrgsForSG' => array('perm_sharing_group'),
            'fetchSGOrgRow' => array('*'),
            'getUUIDs' => array('perm_sync'),
            'index' => ['organisation_index'],
            'view' => array('*'),
        ),
        'pages' => array(
            'display' => array('*'),
        ),
        'posts' => array(
            'add' => ['AND' => ['not_read_only_authkey', 'discussion_enabled', 'perm_add']],
            'delete' => ['AND' => ['not_read_only_authkey', 'discussion_enabled', 'perm_add']],
            'edit' => ['AND' => ['not_read_only_authkey', 'discussion_enabled', 'perm_add']],
            'pushMessageToZMQ' => array()
        ),
        'regexp' => array(
            'admin_add' => array('perm_regexp_access'),
            'admin_clean' => array(),
            'admin_delete' => array('perm_regexp_access'),
            'admin_edit' => array('perm_regexp_access'),
            'admin_index' => array('perm_regexp_access'),
            'cleanRegexModifiers' => array(),
            'index' => array('*'),
        ),
        'restClientHistory' => array(
            'delete' => array('not_read_only_authkey'),
            'index' => array('*')
        ),
        'roles' => array(
            'admin_add' => array(),
            'admin_delete' => array(),
            'admin_edit' => array(),
            'admin_set_default' => array(),
            'index' => array('*'),
            'view' => array('*'),
        ),
        'servers' => array(
            'add' => array(),
            'dbSchemaDiagnostic' => array(),
            'dbConfiguration' => array(),
            'cache' => array(),
            'changePriority' => array(),
            'checkout' => array(),
            'clearWorkerQueue' => array(),
            'createSync' => array('perm_sync'),
            'delete' => array(),
            'deleteFile' => array(),
            'edit' => array(),
            'eventBlockRule' => array(),
            'fetchServersForSG' => array('perm_sharing_group'),
            'filterEventIndex' => array(),
            'getAvailableSyncFilteringRules' => array('*'),
            'getInstanceUUID' => array('perm_sync'),
            'getPyMISPVersion' => array('*'),
            'getRemoteUser' => array(),
            'getSetting' => array(),
            'getSubmodulesStatus' => array(),
            'getSubmoduleQuickUpdateForm' => array(),
            'getWorkers' => array(),
            'getVersion' => array('perm_auth'),
            'idTranslator' => ['host_org_user'],
            'import' => array(),
            'index' => array(),
            'ipUser' => ['perm_site_admin'],
            'ondemandAction' => array(),
            'postTest' => array('*'),
            'previewEvent' => array(),
            'previewIndex' => array(),
            'compareServers' => [],
            'pull' => array(),
            'purgeSessions' => array(),
            'push' => array(),
            'queryAvailableSyncFilteringRules' => array(),
            'releaseUpdateLock' => array(),
            'resetRemoteAuthKey' => array(),
            'removeOrphanedCorrelations' => array(),
            'restartDeadWorkers' => array(),
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
            'killAllWorkers' => [],
            'cspReport' => ['*'],
            'pruneDuplicateUUIDs' => array(),
            'removeDuplicateEvents' => array(),
            'upgrade2324' => array(),
            'cleanModelCaches' => array(),
            'updateDatabase' => array(),
            'rest' => ['perm_auth'],
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
            'generateCorrelation' => array(),
            'index' => array('*'),
            'view' => array('*'),
            'viewPicture' => array('*'),
        ),
        'sharingGroupBlueprints' => array(
            'add' => array('perm_sharing_group'),
            'delete' => array('perm_sharing_group'),
            'detach' => array('perm_sharing_group'),
            'edit' => array('perm_sharing_group'),
            'encodeSyncRule' => ['perm_site_admin'],
            'execute' => array('perm_sharing_group'),
            'generateUuidList' => ['perm_sharing_group'],
            'index' => array('perm_sharing_group'),
            'view' => array('perm_sharing_group'),
            'viewOrgs' => array('perm_sharing_group'),
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
        'sightingBlocklists' => [
            'index' => [],
            'add' => [],
            'delete' => [],
            'edit' => []
        ],
        'sightings' => array(
            'add' => array('perm_sighting'),
            'restSearch' => array('*'),
            'advanced' => array('perm_sighting'),
            'delete' => ['AND' => ['perm_sighting', 'perm_modify_org']],
            'index' => array('*'),
            'view' => array('*'),
            'listSightings' => array('*'),
            'quickDelete' => ['AND' => ['perm_sighting', 'perm_modify_org']],
            'viewSightings' => array('*'),
            'bulkSaveSightings' => array('OR' => array('perm_sync', 'perm_sighting')),
            'filterSightingUuidsForPush' => ['perm_sync'],
            'quickAdd' => array('perm_sighting')
        ),
        'sightingdb' => array(
            'add' => array(),
            'edit' => array(),
            'delete' => array(),
            'index' => array(),
            'requestStatus' => array(),
            'search' => array()
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
            'modifyTagRelationship' => ['perm_tagger'],
            'quickAdd' => array('perm_tag_editor'),
            'removeTagFromObject' => array('perm_tagger'),
            'search' => array('*'),
            'selectTag' => array('perm_tagger'),
            'selectTaxonomy' => array('perm_tagger'),
            'showEventTag' => array('*'),
            'showAttributeTag' => array('*'),
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
            'taxonomy_tags' => array('*'),
            'taxonomyMassConfirmation' => array('perm_tagger'),
            'taxonomyMassHide' => array('perm_tagger'),
            'taxonomyMassUnhide' => array('perm_tagger'),
            'toggleRequired' => array(),
            'toggleHighlighted' => array(),
            'update' => array(),
            'import' => [],
            'export' => ['*'],
            'view' => array('*'),
            'unhideTag' => array('perm_tagger'),
            'hideTag' => array('perm_tagger'),
            'normalizeCustomTagsToTaxonomyFormat' => [],
        ),
        'taxiiServers' => [
            'add' => ['perm_site_admin'],
            'edit' => ['perm_site_admin'],
            'collectionsIndex' => ['perm_site_admin'],
            'index' => ['perm_site_admin'],
            'objectsIndex' => ['perm_site_admin'],
            'objectView' => ['perm_site_admin'],
            'delete' => ['perm_site_admin'],
            'view' => ['perm_site_admin'],
            'push' => ['perm_site_admin'],
            'getRoot' => ['perm_site_admin'],
            'getCollections' => ['perm_site_admin']
        ],
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
            'index' => array('discussion_enabled'),
            'view' => array('discussion_enabled'),
            'viewEvent' => array('discussion_enabled'),
        ),
        'users' => array(
            'acceptRegistrations' => array(),
            'admin_add' => ['AND' => ['perm_admin', 'add_user_enabled']],
            'admin_delete' => array('perm_admin'),
            'admin_destroy' => array(),
            'admin_edit' => array('perm_admin'),
            'admin_email' => array('perm_admin'),
            'admin_filterUserIndex' => array('perm_admin'),
            'admin_index' => array('perm_admin'),
            'admin_massToggleField' => array('perm_admin'),
            'admin_monitor' => array(),
            'admin_quickEmail' => array('perm_admin'),
            'admin_view' => array('perm_admin'),
            'attributehistogram' => array('*'),
            'change_pw' => ['AND' => ['self_management_enabled', 'password_change_enabled', 'not_read_only_authkey']],
            'checkAndCorrectPgps' => array(),
            'checkIfLoggedIn' => array('*'),
            'dashboard' => array('*'),
            'delete' => array('perm_admin'),
            'discardRegistrations' => array(),
            'downloadTerms' => array('*'),
            'edit' => array('self_management_enabled'),
            'email_otp' => array('*'),
            'forgot' => ['AND' => ['password_forgotten_enabled', 'password_change_enabled']],
            'heartbeat' => ['*'],
            'otp' => ['otp_enabled'],
            'hotp' => ['otp_enabled'],
            'totp_new' => ['otp_enabled'],
            'totp_delete' => ['AND' => ['perm_admin', 'otp_enabled']],
            'searchGpgKey' => array('*'),
            'fetchGpgKey' => array('*'),
            'histogram' => array('*'),
            'initiatePasswordReset' => ['AND' => ['perm_admin', 'password_change_enabled']],
            'login' => array('*'),
            'logout' => array('*'),
            'logout401' => array('*'),
            'notificationSettings' => ['*'],
            'password_reset' => ['AND' => ['password_forgotten_enabled', 'password_change_enabled']],
            'register' => array('*'),
            'registrations' => array(),
            'resetAllSyncAuthKeys' => array(),
            'resetauthkey' => ['AND' => ['self_management_enabled', 'perm_auth', 'not_read_only_authkey']],
            'request_API' => array('*'),
            'routeafterlogin' => array('*'),
            'statistics' => array('*'),
            'tagStatisticsGraph' => array('*'),
            'terms' => array('*'),
            'updateLoginTime' => array('*'),
            'updateToAdvancedAuthKeys' => array(),
            'verifyCertificate' => array(),
            'verifyGPG' => array(),
            'view' => array('*'),
            'viewPeriodicSummary' => ['*'],
            'getGpgPublicKey' => array('*'),
            'unsubscribe' => ['*'],
            'view_login_history' => ['*']
        ),
        'userLoginProfiles' => array(
            'index' => ['*'],
            'trust' => ['*'],
            'malicious' => ['*'],
            'admin_delete' => ['perm_admin']
        ),
        'userSettings' => array(
            'index' => array('*'),
            'view' => array('*'),
            'setSetting' => array('not_read_only_authkey'),
            'getSetting' => array('*'),
            'delete' => array('not_read_only_authkey'),
            'setHomePage' => array('not_read_only_authkey'),
            'eventIndexColumnToggle' => ['*'],
        ),
        'warninglists' => array(
            'checkValue' => ['*'],
            'delete' => ['perm_warninglist'],
            'enableWarninglist' => ['perm_warninglist'],
            'getToggleField' => ['perm_warninglist'],
            'index' => array('*'),
            'toggleEnable' => ['perm_warninglist'],
            'update' => array(),
            'view' => array('*'),
            'edit' => ['perm_warninglist'],
            'add' => ['perm_warninglist'],
            'export' => ['*'],
            'import' => ['perm_warninglist'],
        ),
        'workflows' => [
            'index' => [],
            'rebuildRedis' => [],
            'edit' => [],
            'delete' => [],
            'view' => [],
            'editor' => [],
            'triggers' => [],
            'moduleIndex' => [],
            'moduleView' => [],
            'toggleModule' => [],
            'checkGraph' => [],
            'executeWorkflow' => [],
            'debugToggleField' => [],
            'massToggleField' => [],
            'moduleStatelessExecution' => [],
        ],
        'workflowBlueprints' => [
            'add' => [],
            'delete' => [],
            'edit' => [],
            'export' => [],
            'import' => [],
            'index' => [],
            'update' => [],
            'view' => [],
        ],
        'allowedlists' => array(
            'admin_add' => array('perm_regexp_access'),
            'admin_delete' => array('perm_regexp_access'),
            'admin_edit' => array('perm_regexp_access'),
            'admin_index' => array('perm_regexp_access'),
            'index' => array('*'),
        ),
        'eventGraph' => array(
            'view' => array('*'),
            'viewPicture' => array('*'),
            'add' => array('perm_add'),
            'delete' => array('perm_modify'),
        )
    );

    private $dynamicChecks = [];

    /** @var int */
    private $hostOrgId;

    public function __construct(ComponentCollection $collection, $settings = array())
    {
        parent::__construct($collection, $settings);

        $this->hostOrgId = (int)Configure::read('MISP.host_org_id');

        $this->dynamicChecks['host_org_user'] = function (array $user) {
            return (int)$user['org_id'] === $this->hostOrgId;
        };
        $this->dynamicChecks['self_management_enabled'] = function (array $user) {
            if (Configure::read('MISP.disableUserSelfManagement') && !$user['Role']['perm_admin']) {
                throw new ForbiddenException('User self-management has been disabled on this instance.');
            }
            return true;
        };
        $this->dynamicChecks['password_change_enabled'] = function ($user) {
            if (Configure::read('MISP.disable_user_password_change')) {
                throw new ForbiddenException('User password change has been disabled on this instance.');
            }
            return true;
        };
        $this->dynamicChecks['otp_enabled'] = function ($user) {
            if (Configure::read('Security.otp_disabled')) {
                throw new ForbiddenException('OTP has been disabled on this instance.');
            }
            return true;
        };
        $this->dynamicChecks['password_forgotten_enabled'] = function ($user) {
            if (empty(Configure::read('Security.allow_password_forgotten'))) {
                throw new ForbiddenException('Password reset has been disabled on this instance.');
            }
            return true;
        };
        $this->dynamicChecks['add_user_enabled'] = function (array $user) {
            if (Configure::read('MISP.disable_user_add')) {
                throw new ForbiddenException('Adding users has been disabled on this instance.');
            }
            return true;
        };
        $this->dynamicChecks['delegation_enabled'] = function (array $user) {
            return (bool)Configure::read('MISP.delegation');
        };
        $this->dynamicChecks['discussion_enabled'] = function (array $user) {
            return !Configure::read('MISP.discussion_disable');
        };
        // Returns true if current user is not using advanced auth key or if authkey is not read only
        $this->dynamicChecks['not_read_only_authkey'] = function (array $user) {
            return !isset($user['authkey_read_only']) || !$user['authkey_read_only'];
        };
        // If `Security.hide_organisation_index_from_users` is enabled, only user with sharing group permission can see org index
        $this->dynamicChecks['organisation_index'] = function (array $user) {
            if (Configure::read('Security.hide_organisation_index_from_users')) {
                return $user['Role']['perm_sharing_group'];
            }
            return true;
        };
    }

    /**
     * Returns true if user can modify given event.
     *
     * @param array $event
     * @param array $user
     * @return bool
     */
    public function canModifyEvent(array $user, array $event)
    {
        if (!isset($event['Event'])) {
            throw new InvalidArgumentException('Passed object does not contain an Event.');
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($user['Role']['perm_modify_org'] && $event['Event']['orgc_id'] == $user['org_id']) {
            return true;
        }
        if ($user['Role']['perm_modify'] && $event['Event']['user_id'] == $user['id']) {
            return true;
        }
        return false;
    }

    /**
     * Returns true if user can publish the given event.
     *
     * @param array $user
     * @param array $event
     * @return bool
     */
    public function canPublishEvent(array $user, array $event)
    {
        if (!isset($event['Event'])) {
            throw new InvalidArgumentException('Passed object does not contain an Event.');
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($user['Role']['perm_publish'] && $event['Event']['orgc_id'] == $user['org_id']) {
            return true;
        }
        return false;
    }

    /**
     * Returns true if user can add or remove tags for given event.
     *
     * @param array $user
     * @param array $event
     * @param bool $isTagLocal
     * @return bool
     */
    public function canModifyTag(array $user, array $event, $isTagLocal = false)
    {
        if (!isset($event['Event'])) {
            throw new InvalidArgumentException('Passed object does not contain an Event.');
        }
        // Site admin can add any tag
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        // User must have tagger or sync permission
        if (!$user['Role']['perm_tagger'] && !$user['Role']['perm_sync']) {
            return false;
        }
        if ($this->canModifyEvent($user, $event)) {
            return true; // full access
        }
        if ($isTagLocal && $this->hostOrgId === (int)$user['org_id']) {
            return true;
        }
        return false;
    }

    /**
     * @param array $user
     * @param array $event
     * @return bool
     */
    public function canDisableCorrelation(array $user, array $event)
    {
        if (Configure::read('MISP.completely_disable_correlation')) {
            return false; // correlations are completely disabled
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        return Configure::read('MISP.allow_disabling_correlation') && $this->canModifyEvent($user, $event);
    }

    /**
     * @param array $user
     * @param array $tagCollection
     * @return bool
     */
    public function canModifyTagCollection(array $user, array $tagCollection)
    {
        if (!isset($tagCollection['TagCollection'])) {
            throw new InvalidArgumentException('Passed object does not contain a TagCollection.');
        }
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        return $user['org_id'] == $tagCollection['TagCollection']['org_id'];
    }

    /**
     * Only users that can modify organisation can delete sightings as sighting is not linked to user.
     *
     * @param array $user
     * @param array $sighting
     * @return bool
     */
    public function canDeleteSighting(array $user, array $sighting)
    {
        if (!isset($sighting['Sighting'])) {
            throw new InvalidArgumentException('Passed object does not contain a Sighting.');
        }
        // Site admin can delete any sighting
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (!$user['Role']['perm_modify_org']) {
            return false;
        }
        return $sighting['Sighting']['org_id'] == $user['org_id'];
    }

    /**
     * @param array $user
     * @param array $eventReport
     * @return bool
     */
    public function canEditEventReport(array $user, array $eventReport)
    {
        if (!isset($eventReport['Event'])) {
            throw new InvalidArgumentException('Passed object does not contain an Event.');
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($eventReport['Event']['orgc_id'] == $user['org_id']) {
            return true;
        }
        return false;
    }

    /**
     * Checks if user can modify given galaxy cluster
     *
     * @param array $user
     * @param array $cluster
     * @return bool
     */
    public function canModifyGalaxyCluster(array $user, array $cluster)
    {
        if (!isset($cluster['GalaxyCluster'])) {
            throw new InvalidArgumentException('Passed object does not contain an GalaxyCluster.');
        }
        if ($cluster['GalaxyCluster']['default']) {
            return false; // it is not possible to edit default clusters
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (!$user['Role']['perm_galaxy_editor']) {
            return false;
        }
        return $cluster['GalaxyCluster']['orgc_id'] == $user['org_id'];
    }

    /**
     * Checks if user can modify given analyst data
     *
     * @param array $user
     * @param array $analystData
     * @param string $modelType
     * @return bool
     */
    public function canEditAnalystData(array $user, array $analystData, $modelType): bool
    {
        if (!isset($analystData[$modelType])) {
            throw new InvalidArgumentException('Passed object does not contain a(n) ' . $modelType);
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if ($analystData[$modelType]['orgc_uuid'] == $user['Organisation']['uuid']) {
            return true;
        }
        return false;
    }

    /**
     * Checks if user can publish given galaxy cluster
     *
     * @param array $user
     * @param array $cluster
     * @return bool
     */
    public function canPublishGalaxyCluster(array $user, array $cluster)
    {
        if (!$this->canModifyGalaxyCluster($user, $cluster)) {
            return false;
        }
        return (bool)$user['Role']['perm_publish'];
    }

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
                        $this->Log->saveOrFailSilently(array(
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

    /**
     * @param array $user
     * @param string $controller
     * @param string $action
     * @return bool
     */
    public function canUserAccess($user, $controller, $action)
    {
        try {
            $this->checkAccess($user, $controller, $action, false);
        } catch (NotFoundException $e) {
            throw new RuntimeException("Invalid controller '$controller' specified.", 0, $e);
        } catch (ForbiddenException $e) {
            return false;
        }
        return true;
    }

    /**
     * The check works like this:
     * - If the user is a site admin, return true
     * - If the requested action has an OR-d list, iterate through the list. If any of the permissions are set for the user, return true
     * - If the requested action has an AND-ed list, iterate through the list. If any of the permissions for the user are not set, turn the check to false. Otherwise return true.
     * - If the requested action has a permission, check if the user's role has it flagged. If yes, return true
     * - If we fall through all of the checks, return an exception.
     *
     * @param array|null $user
     * @param string $controller
     * @param string $action
     * @param bool $checkLoggedActions
     * @return true
     * @throws NotFoundException
     * @throws ForbiddenException
     */
    public function checkAccess($user, $controller, $action, $checkLoggedActions = true)
    {
        $controller = lcfirst(Inflector::camelize($controller));
        $action = strtolower($action);
        if ($checkLoggedActions) {
            $this->__checkLoggedActions($user, $controller, $action);
        }
        if (!isset(self::ACL_LIST[$controller])) {
            throw new NotFoundException('Invalid controller.');
        }
        $controllerAclList = array_change_key_case(self::ACL_LIST[$controller]);
        if (!empty($controllerAclList[$action])) {
            $rules = $controllerAclList[$action];
            if (in_array('*', $rules, true)) {
                return true;
            }
            if (isset($rules['OR'])) {
                foreach ($rules['OR'] as $permission) {
                    if (isset($this->dynamicChecks[$permission])) {
                        if ($this->dynamicChecks[$permission]($user)) {
                            return true;
                        }
                    } else {
                        if ($user['Role'][$permission]) {
                            return true;
                        }
                    }
                }
            } elseif (isset($rules['AND'])) {
                $allConditionsMet = true;
                foreach ($rules['AND'] as $permission) {
                    if (isset($this->dynamicChecks[$permission])) {
                        if (!$this->dynamicChecks[$permission]($user)) {
                            $allConditionsMet = false;
                        }
                    } else {
                        if (!$user['Role'][$permission]) {
                            $allConditionsMet = false;
                        }
                    }
                }
                if ($allConditionsMet) {
                    return true;
                }
            } elseif (isset($this->dynamicChecks[$rules[0]])) {
                if ($this->dynamicChecks[$rules[0]]($user)) {
                    return true;
                }
            } elseif ($user['Role'][$rules[0]]) {
                return true;
            }
        }
        // Dynamic checks can raise forbidden exception even for site admins, so we have to check permission for site
        // admin as last thing.
        if ($user && $user['Role']['perm_site_admin']) {
            return true;
        }
        throw new ForbiddenException('You do not have permission to use this functionality.');
    }

    private function __findAllFunctions()
    {
        $functionsToIgnore = ['beforeFilter', 'afterFilter', 'beforeRender',  'getEventManager'];

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
            $fileContents = FileAccessTool::readFromFile(APP . 'Controller' . DS . $file);
            $fileContents = preg_replace('/\/\*[^\*]+?\*\//', '', $fileContents);
            preg_match_all($functionFinder, $fileContents, $functionArray);
            foreach ($functionArray[1] as $function) {
                if ($function[0] !== '_' && !in_array($function, $functionsToIgnore, true)) {
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
                if (!isset(self::ACL_LIST[$controller]) || !in_array($function, array_keys(self::ACL_LIST[$controller]))) {
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

    private function __checkRoleAccess(array $role)
    {
        $result = array();
        $fakeUser = ['Role' => $role, 'org_id' => $this->hostOrgId];
        foreach (self::ACL_LIST as $controller => $actions) {
            $controllerNames = Inflector::variable($controller) === Inflector::underscore($controller) ?
                array(Inflector::variable($controller)) :
                array(Inflector::variable($controller), Inflector::underscore($controller));
            foreach ($controllerNames as $controllerName) {
                foreach ($actions as $action => $permissions) {
                    if ($this->canUserAccess($fakeUser, $controllerName, $action)) {
                        $result[] = "/$controllerName/$action";
                    }
                }
            }
        }
        return $result;
    }
}
