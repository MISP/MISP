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
            'queryACL' => array(),
            'restSearch' => array('*'),
        ),
        'analystData' => [
            'add' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'delete' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'deleteSelection' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'edit' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'filterAnalystDataForPush' => ['perm_sync'],
            'getChildren' => ['*'],
            'getRelatedElement' => ['*'],
            'index' => ['*'],
            'indexMinimal' => ['*'],
            'pushAnalystData' => ['perm_sync'],
            'pushAnalystDataBatch' => ['perm_sync'],
            'view' => ['*'],
            'viewForObject' => ['theming_enabled'],
        ],
        'analystDataBlocklists' => array(
            'add' => array(),
            'delete' => array(),
            'deleteSelection' => array(),
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
            'addTag' => array('perm_tagger'),
            'attributeReplace' => array('perm_add'),
            'attributeStatistics' => array('*'),
            'bro' => array('*'),
            'checkAttachments' => array(),
            'delete' => array('perm_add'),
            'deleteSelection' => array('AND' => ['theming_enabled', 'perm_add']),
            'deleteSelected' => array('perm_add'),
            'describeTypes' => array('*'),
            'download' => array('*'),
            'downloadAttachment' => array('*'),
            'downloadSample' => array('*'),
            'edit' => array('perm_add'),
            'editAttributeGalaxies' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'editAttributeGalaxyRelationships' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'editAttributeTags' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'editAttributeTagRelationships' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'editField' => array('perm_add'),
            'editSelected' => array('perm_add'),
            'enrich' => ['perm_add'],
            'fetchEditForm' => array('perm_add'),
            'fetchViewValue' => array('*'),
            'galaxySelection' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'generateCorrelation' => array(),
            'getAttributeByB64Value' => ['*'],
            'getMassEditForm' => array('perm_add'),
            'getInstanceCache' => ['*'],
            'hoverEnrichment' => array('perm_add'),
            'index' => array('*'),
            'removeTag' => array('perm_tagger'),
            'restore' => array('perm_add'),
            'restSearch' => array('*'),
            'returnAttributes' => array('*'),
            'rpz' => array('*'),
            'search' => array('*'),
            'tagSelection' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'toggleCorrelation' => array('perm_add'),
            'text' => array('*'),
            'toggleToIDS' => array('perm_add'),
            'validateValue' => array('AND' => ['perm_add', 'theming_enabled']),
            'view' => array('*'),
            'viewAnalystData' => ['*'],
            'viewPicture' => array('*'),
        ),
        'authKeys' => [
            'add' => ['AND' => ['perm_auth', 'not_read_only_authkey']],
            'delete' => ['AND' => ['perm_auth', 'not_read_only_authkey']],
            'deleteSelection' => ['AND' => ['perm_auth', 'not_read_only_authkey', 'theming_enabled']],
            'edit' => ['AND' => ['perm_auth', 'not_read_only_authkey']],
            'pin' => ['AND' => ['perm_auth', 'not_read_only_authkey']],
            'revoke' => ['AND' => ['perm_auth', 'not_read_only_authkey', 'theming_enabled']],
            'index' => ['perm_auth'],
            'view' => ['perm_auth'],
        ],
        'benchmarks' => [
            'index' => [],
            'purgeSqlMetrics' => [],
            'sqlMetrics' => []
        ],
        'bookmarks' => [
            'add' => ['*'],
            'delete' => ['*'],
            'deleteSelection' => ['*'],
            'edit' => ['*'],
            'index' => ['*'],
            'panel' => ['*'],
            'view' => ['*'],
        ],
        'cerebrates' => [
            'add' => [],
            'delete' => [],
            'deleteSelection' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
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
            // Sync push-receive upload endpoint → Collection::captureCollection sink.
            'captureCollection' => ['perm_sync'],
            'delete' => ['perm_modify'],
            'deleteSelection' => ['AND'=> ['perm_modify', 'theming_enabled']],
            'edit' => ['perm_modify'],
            // Sync push-receive dedup handshake (returns the UUIDs the local side wants).
            'filterCollectionsForPush' => ['perm_sync'],
            // Read-only JSON endpoint used by beta Event view to list collection memberships.
            'getCollectionsForElement' => ['*'],
            'getCollectionsForElements' => ['*'],
            'index' => ['*'],
            'indexMinimal' => ['*'],
            'view' => ['*']
        ],
        'collectionElements' => [
            'add' => ['perm_modify'],
            'addElementToCollection' => ['perm_modify'],
            'delete' => ['perm_modify'],
            'deleteSelection' => ['AND'=> ['perm_modify', 'theming_enabled']],
            'index' => ['*']
        ],
        'correlationExclusions' => [
            'add' => [],
            'edit' => [],
            'clean' => [],
            'delete' => [],
            'deleteSelection' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
            'index' => [],
            'view' => []
        ],
        'correlationRules' => [
            'index' => [],
            'add' => [],
            'edit' => [],
            'executeRule' => [],
            'delete' => [],
            'deleteSelection' => [],
        ],
        'correlations' => [
            'eventCorrelations' => ['*'],
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
            'serverSign' => ['perm_server_sign'],
            'view' => ['*']
        ],
        'dashboards' => array(
            'index' => array('*'),
            'widgets' => array('*'),
            'updateSettings' => array('*'),
            'updateWidgetSettings' => array('*'),
            'renderWidget' => array('*'),
            'renderWrapper' => array('*'),
            'import' => array('*'),
            'export' => array('*'),
            'saveTemplate' => array('*'),
            'listTemplates' => array('*'),
            'deleteTemplate' => array('*'),
            'importDefaultTemplates' => array(),
            'invalidateUserSessions' => array(),
            'listSharingGroups' => array('*'),
            'listGalaxyTypes' => array('*'),
            'searchGalaxyClusters' => array('*'),
            'searchOrganisations' => array('*'),
            'updateTheme' => ['*'],
            'resetFromTemplate' => ['*']
        ),
        /*
         * The Analyst Profile editor (prd/analyst-profile/09-editor.md,
         * phase 8a). D13: **no new permission flag.** A profile a user
         * owns changes only their own pages, so it needs no grant —
         * the same reasoning that leaves `user_settings` ungated. An
         * organisation profile changes what colleagues read and the
         * shipped default changes what everybody reads, so both are
         * narrower than the ACL can express: the model's
         * `isEditableByCurrentUser()` decides, on every write.
         *
         * Which is why `edit`, `fork`, `delete`, `enable` and `disable`
         * are `*` rather than `perm_admin`. An ACL entry naming a
         * permission here would be a second opinion about the same
         * question, and two of those is how the looser one becomes the
         * answer. `update` is the exception, because loading the
         * shipped defaults is not about any one profile's owner.
         */
        'analystProfiles' => array(
            'index' => array('*'),
            'view' => array('*'),
            'edit' => array('*'),
            'fork' => array('*'),
            'delete' => array('*'),
            'enable' => array('*'),
            'disable' => array('*'),
            'select' => array('*'),
            'deselect' => array('*'),
            'share' => array(),
            'unshare' => array(),
            'export' => array('*'),
            'import' => array('*'),
            'simulate' => array('*'),
            'pin' => array('*'),
            'unpin' => array('*'),
            'grade' => array('*'),
            'update' => array(),
            'enrichment' => array('*'),
            'fix' => array(),
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
            "deleteSelection" => array('AND' => array('perm_decaying_or_admin', 'theming_enabled')),
            "enable" => array('OR' => array('perm_admin', 'perm_decaying')),
            "disable" => array('OR' => array('perm_admin', 'perm_decaying')),
            "massEnable" => array('AND' => array('perm_decaying_or_admin', 'theming_enabled')),
            "massDisable" => array('AND' => array('perm_decaying_or_admin', 'theming_enabled')),
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
            ],
            'deleteSelection' => [
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
            'viewRendered' => array('*'),
            'edit' => array('perm_add'),
            'delete' => array('perm_add'),
            'deleteSelection' => array('AND' => ['theming_enabled', 'perm_add']),
            'reportFromEvent' => array('perm_add'),
            'restore' => array('perm_add'),
            'aiExtractIndicators' => array('perm_ai_tools'),
            'aiSummarize' => array('perm_ai_tools'),
            'index' => array('*'),
            'getProxyMISPElements' => array('*'),
            'extractAllFromReport' => array('perm_add'),
            'extractFromReport' => array('perm_add'),
            'replaceSuggestionInReport' => array('perm_add'),
            'importReportFromUrl' => array('perm_add'),
            'downloadAsPDF' => ['*'],
            'addTag' => ['perm_tagger'],
            'removeTag' => ['perm_tagger'],
            'uploadPicture' => ['perm_add'],
            'viewPicture' => ['*'],
            'managedImportedPictures' => [],
            'deletePicture' => [],
            'purgeUnusedPictures' => [],
            'setFileAlias' => []
        ),
        'eventReportTemplateVariables' => array(
            'add' => [],
            'view' => ['*'],
            'edit' => [],
            'delete' => [],
            'deleteSelection' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
            'index' => ['*'],
        ),
        'eventTemplates' => array(
            'index' => array('*'),
            'view' => array('*'),
            // Exposed-only listing — the Draugnet pull contract. Read action,
            // gated by the same visibility conditions as index/view.
            'exposed' => array('*'),
            'add' => array('perm_template'),
            'edit' => array('perm_template'),
            'delete' => array('perm_template'),
            'deleteSelection' => array('AND' => ['theming_enabled', 'perm_template']),
            'duplicate' => array('perm_template'),
            'export' => array('*'),
            'import' => array('perm_template'),
            'instantiate' => array('perm_add'),
            'preview' => array('perm_template'),
            'validate_definition' => array('perm_template'),
            // Library updates affect every org on the instance — site_admin only.
            'update' => array(),
            'library_status' => array(),
        ),
        'events' => array(
            'add' => array('perm_add'),
            'addTag' => array('perm_tagger'),
            'add_misp_export' => array('perm_modify'),
            'aiActions' => array('perm_ai_tools'),
            'aiExtractIndicators' => array('perm_ai_tools'),
            'aiRecommendTags' => array('perm_ai_tools'),
            'aiSummarize' => array('perm_ai_tools'),
            'alert' => array('perm_publish'),
            'automation' => array('perm_auth'),
            'cardElements' => array('*'),
            'checkLocks' => array('perm_add'),
            'checkPublishedStatus' => array('*'),
            'contact' => array('*'),
            'correlatedAttributes' => array('*'),
            'correlationCounts' => array('*'),
            'csv' => array('*'),
            'cullEmptyEvents' => array(),
            'delete' => array('perm_add'),
            'edit' => array('perm_add'),
            'editEventTags' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'editEventTagRelationships' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'editEventGalaxies' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'editEventGalaxyRelationships' => array('AND' => ['perm_tagger', 'theming_enabled']),
            'enrichEvent' => array('perm_add'),
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
            'getObjectTemplate' => array('*'),
            'graph' => array('*'),
            'handleModuleResults' => array('*'),
            'hids' => array('*'),
            'index' => array('*'),
            'importChoice' => array('*'),
            'importEvent' => array('AND' => ['perm_modify', 'theming_enabled']),
            'importModule' => array('*'),
            'merge' => array('perm_modify'),
            'nids' => array('*'),
            'populate' => array('perm_add'),
            'populateFrom' => array('AND' => ['perm_add', 'theming_enabled']),
            'proposalEventIndex' => array('*'),
            'protect' => ['perm_add'],
            'publish' => array('perm_publish'),
            'publishSightings' => array('perm_sighting'),
            'pushEventToZMQ' => array('perm_publish_zmq'),
            'pushEventToKafka' => array('perm_publish_kafka'),
            'pushProposals' => array('perm_sync'),
            'queryEnrichment' => array('perm_add'),
            'recorrelateEvent' => [],
            'removePivot' => array('*'),
            'removeTag' => array('perm_tagger'),
            'restSearch' => array('*'),
            'restSearchExport' => array('*'),
            'runTaxonomyExclusivityCheck' => array('*'),
            'runWorkflow' => array(),
            // The Pivot Explorer's Save of enrichment results; the event
            // itself is checked in the action.
            'saveEnrichment' => array(
                'AND' => array('perm_add', 'theming_enabled')
            ),
            'saveFreeText' => array('perm_add'),
            'searchGalaxyClusters' => array('theming_enabled'),
            'stix' => array('*'),
            'stix2' => array('*'),
            'taggedEvents' => array('*'),
            'toggleCorrelation' => array('perm_add'),
            'unprotect' => ['perm_add'],
            'unpublish' => array('perm_modify'),
            'updateGraph' => array('*'),
            'upload_analysis_file' => array('perm_add'),
            'upload_sample' => array('AND' => array('perm_auth', 'perm_add')),
            'upload_stix' => array('perm_modify'),
            'view' => array('*'),
            'view1' => array('*'),
            'view2' => array('*'),
            'viewLegacy' => array('*'),
            'viewAttributes' => array('theming_enabled'),
            'viewObjects' => array('theming_enabled'),
            'viewEventReports' => array('theming_enabled'),
            'viewEventTags' => array('theming_enabled'),
            'viewEventGalaxies' => array('theming_enabled'),
            'viewEventInventory' => array('theming_enabled'),
            'viewEventObjectViews' => array('theming_enabled'),
            'viewEventContext' => array('theming_enabled'),
            'viewEventMatrix' => array('theming_enabled'),
            'viewEventGalaxyMatrix' => array('theming_enabled'),
            'viewEventOverviewGraph' => array('theming_enabled'),
            'viewEventActivity' => array('theming_enabled'),
            'viewEventTimeline' => array('theming_enabled'),
            'viewAttachments' => array('theming_enabled'),
            'viewEventSightings' => array('theming_enabled'),
            'viewRelatedEvents' => array('theming_enabled'),
            'viewWarninglistHits' => array('theming_enabled'),
            'viewEventAttributes' => array('*'),
            'viewGraph' => array('*'),
            'viewGalaxyMatrix' => array('*'),
            'xml' => array('*'),
            'addEventLock' => ['perm_auth'],
            'removeEventLock' => ['perm_auth'],
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
            'deleteSelection' => ['AND' => ['perm_site_admin', 'theming_enabled']],
            'disable' => array(),
            'edit' => array(),
            'enable' => array(),
            'feedCoverage' => ['host_org_user'],
            'fetchFromAllFeeds' => array(),
            'fetchFromFeed' => array(),
            'fetchSelectedFeeds' => ['AND' => ['perm_site_admin', 'theming_enabled']],
            'fetchSelectedFromFreetextIndex' => array(),
            'getEvent' => array(),
            'getSelectedEvents' => ['AND' => ['perm_site_admin', 'theming_enabled']],
            'importFeeds' => ['AND' => ['perm_site_admin', 'theming_enabled']],
            'index' => ['*'],
            'loadDefaultFeeds' => array(),
            'manifestEvents' => ['*'],
            'previewEvent' => ['*'],
            'previewEventAttributes' => ['theming_enabled'],
            'previewEventObjects' => ['theming_enabled'],
            'previewIndex' => ['*'],
            'railCard' => ['host_org_user'],
            'searchCaches' => ['*'],
            'toggleSelected' => array(),
            'view' => ['host_org_user'],
        ),
        'galaxies' => array(
            'attachCluster' => array('perm_tagger'),
            'attachMultipleClusters' => array('perm_tagger'),
            'add' => array('perm_galaxy_editor'),
            'edit' => array('perm_galaxy_editor'),
            'delete' => array('perm_galaxy_editor'),
            'deleteSelection' => array('AND' => ['perm_galaxy_editor', 'theming_enabled']),
            'disable' => array(),
            'enable' => array(),
            'massEnable' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massDisable' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'toggleEnable' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'export' => array('*'),
            'index' => array('*'),
            'import' => array('perm_galaxy_editor'),
            'pickerScopes' => array('*'),
            'pushCluster' => array('perm_sync'),
            'selectGalaxy' => array('perm_tagger'),
            'selectGalaxyNamespace' => array('perm_tagger'),
            'selectCluster' => array('perm_tagger'),
            'showGalaxies' => array('*'),
            'toggle' => array(),
            'update' => array(),
            'railCard' => array('*'),
            'view' => array('*'),
            'viewGraph' => array('*'),
            'viewMatrix' => array('*'),
            'wipe_default' => array(),
        ),
        'galaxyClusterBlocklists' => array(
            'add' => array(),
            'delete' => array(),
            'deleteSelection' => array(),
            'edit' => array(),
            'index' => array(),
            'massDelete' => array(),
        ),
        'galaxyClusters' => array(
            'add' => array('perm_galaxy_editor'),
            'delete' => array('perm_galaxy_editor'),
            'deleteSelection' => array('AND' => ['perm_galaxy_editor', 'theming_enabled']),
            'detach' => array('perm_tagger'),
            'edit' => array('perm_galaxy_editor'),
            'export_for_misp_galaxy' => array('*'),
            'graph' => array('*'),
            'index' => array('*'),
            'pickerSearch' => array('*'),
            'publish' => array('AND' => ['perm_galaxy_editor', 'perm_publish']),
            'railCard' => array('*'),
            'restore' => array('perm_galaxy_editor'),
            'relatedClusters' => array('*'),
            'restSearch' => array('*'),
            'search' => array('*'),
            'unpublish' => array('perm_galaxy_editor'),
            'updateCluster' => array('perm_galaxy_editor'),
            'view' => array('*'),
            'viewGalaxyMatrix' => array('*'),
            'viewMatrix' => array('*'),
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
            'deleteSelection' => array('AND' => ['perm_galaxy_editor', 'theming_enabled']),
            'flattenJson' => array('perm_galaxy_editor'),
            'index' => array('*'),
        ),
        'jobs' => array(
            'getError' => array(),
            'getGenerateCorrelationProgress' => array(),
            'getProgress' => array('*'),
            'index' => array(),
            'clearJobs' => array(),
            'deleteSelection' => array('AND' => ['perm_site_admin', 'theming_enabled']),
        ),
        'logs' => array(
            'admin_index' => array('perm_audit'),
            'event_index' => array('*'),
            'returnDates' => array('*'),
            'index' => array('perm_audit')
        ),
        'auditLogs' => [
            'admin_index' => ['perm_audit'],
            'fullChange' => ['perm_audit'],
            'eventIndex' => ['*'],
            'eventIndexV2' => ['theming_enabled'],
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
            'deleteSelection' => array(),
            'admin_index' => array(),
            'index' => ['*'],
        ),
        'noticelists' => array(
            'delete' => array(),
            'enableNoticelist' => array(),
            'massEnable' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massDisable' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'getToggleField' => array(),
            'index' => array('*'),
            'toggleEnable' => array(),
            'update' => array(),
            'view' => array('*'),
            'preview_entries' => array('*')
        ),
        'objects' => array(
            'add' => array('perm_add'),
            'delete' => array('perm_add'),
            'deleteSelection' => array('AND' => ['perm_add', 'theming_enabled']),
            'edit' => array('perm_add'),
            'get_row' => array('perm_add'),
            'index' => array('*'),
            'indexCard' => array('*'),
            'orphanedObjectDiagnostics' => array(),
            'editField' => array('perm_add'),
            'fetchEditForm' => array('perm_add'),
            'fetchViewValue' => array('*'),
            'quickAddAttributeForm' => array('perm_add'),
            'quickFetchTemplateWithValidObjectAttributes' => array('perm_add'),
            'restSearch' => array('*'),
            'surroundings' => ['*'],
            'proposeObjectsFromAttributes' => array('*'),
            'groupAttributesIntoObject' => array('perm_add'),
            'revise_object' => array('perm_add'),
            'similar_objects' => array('AND' => ['perm_add', 'theming_enabled']),
            'view' => array('*'),
            'viewAnalystData' => ['*'],
            'createFromFreetext' => ['perm_add'],
        ),
        'objectReferences' => array(
            'targets' => array('AND' => ['perm_add', 'theming_enabled']),
            'add' => array('perm_add'),
            'bulkAdd' => array('perm_add'),
            'delete' => array('perm_add'),
            'view' => array('*'),
        ),
        'objectTemplates' => array(
            'activate' => array(),
            'delete' => array('perm_object_template'),
            'deleteSelection' => array('AND' => ['perm_object_template', 'theming_enabled']),
            'toggleActive' => array('AND' => ['perm_object_template', 'theming_enabled']),
            'getToggleField' => array(),
            'getRaw' => array('perm_object_template'),
            'objectChoice' => array('*'),
            'objectMetaChoice' => array('perm_add'),
            'railCard' => array('*'),
            'view' => array('*'),
            'index' => array('*'),
            'update' => array(),
            'possibleObjectTemplates' => ['*'],
        ),
        'objectTemplateElements' => array(
            'viewElements' => array('*')
        ),
        'objectRelationships' => array(
            'index' => array('*'),
            'add' => array(),
            'delete' => array(),
            'deleteSelection' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massHighlight'  => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massRemoveHighlight'  => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'edit' => array(),
            'toggleHighlighted' => array(),
        ),
        'orgBlocklists' => array(
            'add' => array(),
            'delete' => array(),
            'deleteSelection' => array(),
            'edit' => array(),
            'index' => array(),
        ),
        'organisations' => array(
            'admin_add' => array(),
            'admin_delete' => array(),
            'admin_deleteSelection' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'admin_edit' => array(),
            'admin_generateuuid' => array(),
            'admin_merge' => array(),
            'fetchOrgsForSG' => array('perm_sharing_group'),
            'getOrgLogo' => array('*'),
            'index' => ['organisation_index'],
            'pickerSearch' => array('*'),
            'railCard' => array('*'),
            'view' => array('*'),
        ),
        'pages' => array(
            'display' => array('*'),
        ),
        'regexp' => array(
            'admin_add' => array('perm_regexp_access'),
            'admin_clean' => array(),
            'admin_delete' => array('perm_regexp_access'),
            'admin_deleteSelection' => ['AND'=> ['perm_regexp_access', 'theming_enabled']],
            'admin_edit' => array('perm_regexp_access'),
            'admin_index' => array('perm_regexp_access'),
            'index' => array('*'),
        ),
        'restClientHistory' => array(
            'delete' => array('not_read_only_authkey'),
            'index' => array('*')
        ),
        'roles' => array(
            'admin_add' => array(),
            'admin_delete' => array(),
            'admin_deleteSelection' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'admin_edit' => array(),
            'admin_set_default' => array(),
            'admin_togglePermission' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'index' => array('*'),
            'view' => array('*'),
        ),
        'servers' => array(
            'add' => array(),
            'aiDryRun' => array(),
            'dbSchemaDiagnostic' => array(),
            'dbConfiguration' => array(),
            'cache' => array(),
            'changePriority' => array(),
            'checkout' => array(),
            'clearWorkerQueue' => array(),
            'delete' => array(),
            'deleteSelection' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
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
            'index' => array(),
            'ipUser' => ['perm_site_admin'],
            'ondemandAction' => array(),
            'postTest' => array('*'),
            'previewEvent' => ['host_org_user'],
            'previewEventAttributes' => ['AND' => ['host_org_user', 'theming_enabled']],
            'previewEventObjects' => ['AND' => ['host_org_user', 'theming_enabled']],
            'previewIndex' => ['host_org_user'],
            'pull' => array(),
            'pullSelectedEvents' => ['AND' => ['perm_site_admin', 'theming_enabled']],
            'purgeSessions' => array(),
            'push' => array(),
            'queryAvailableSyncFilteringRules' => array(),
            'releaseUpdateLock' => array(),
            'resetRemoteAuthKey' => array(),
            'removeOrphanedCorrelations' => array(),
            'restartDeadWorkers' => array(),
            'restartWorkers' => array(),
            'serverDiagnostic' => ['AND' => ['perm_site_admin', 'theming_enabled']],
            'serverSettings' => array(),
            'serverSettingsEdit' => array(),
            'serverSettingsReloadSetting' => array(),
            'startWorker' => array(),
            'startZeroMQServer' => array(),
            'statusZeroMQServer' => array(),
            'stopWorker' => array(),
            'stopZeroMQServer' => array(),
            'testConnection' => array(),
            'testSyncRules' => [],
            'update' => array(),
            'updateJSON' => array(),
            'updateProgress' => array(),
            'updateSubmodule' => array(),
            'uploadFile' => array(),
            'cspReport' => ['*'],
            'cleanModelCaches' => array(),
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
            'index' => array('*'),
            'view' => array('*'),
            'viewPicture' => array('*'),
        ),
        'sharingGroupBlueprints' => array(
            'add' => array('perm_sharing_group'),
            'delete' => array('perm_sharing_group'),
            'deleteSelection' => ['AND'=> ['perm_sharing_group', 'theming_enabled']],
            'detach' => array('perm_sharing_group'),
            'edit' => array('perm_sharing_group'),
            'encodeSyncRule' => ['perm_site_admin'],
            'execute' => array('perm_sharing_group'),
            'generateUuidList' => ['perm_sharing_group'],
            'index' => array('perm_sharing_group'),
            'railCard' => array('perm_sharing_group'),
            'view' => array('perm_sharing_group'),
            'viewOrgs' => array('perm_sharing_group'),
        ),
        'sharingGroups' => array(
            'add' => array('perm_sharing_group'),
            'addServer' => array('perm_sharing_group'),
            'addOrg' => array('perm_sharing_group'),
            'delete' => array('perm_sharing_group'),
            'deleteSelection' => ['AND'=> ['perm_sharing_group', 'theming_enabled']],
            'edit' => array('perm_sharing_group'),
            'index' => array('*'),
            'pickerSearch' => array('*'),
            'railCard' => array('*'),
            'removeServer' => array('perm_sharing_group'),
            'removeOrg' => array('perm_sharing_group'),
            'view' => array('*'),
        ),
        'sightingBlocklists' => [
            'index' => [],
            'add' => [],
            'delete' => [],
            'deleteSelection' => [],
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
            'deleteSelection' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
            'index' => array(),
            'requestStatus' => array(),
            'search' => array()
        ),
        'tagCollections' => array(
            'add' => array('perm_tag_editor'),
            'addWithTags' => ['AND'=> ['perm_tag_editor', 'theming_enabled']],
            'addTag' => array('perm_tag_editor'),
            'delete' => array('perm_tag_editor'),
            'deleteSelection' => ['AND'=> ['perm_tag_editor', 'theming_enabled']],
            'edit' => array('perm_tag_editor'),
            'editWithTags' => ['AND'=> ['perm_tag_editor', 'theming_enabled']],
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
            'deleteSelection' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'edit' => array(),
            'index' => array('*'),
            'modifyTagRelationship' => ['perm_tagger'],
            'pickerScopes' => array('*'),
            'pickerSearch' => array('*'),
            'pickerTree' => array('*'),
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
            'fastIndex' => array('*'),
        ),
        'tasks' => array(
            'index' => array(),
            'add' => array(),
            'edit' => array(),
            'delete' => array(),
            'deleteSelection' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'toggleEnabled' => array(),
            'forceRun' => array(),
            'viewLogs' => array(),
        ),
        'taxonomies' => array(
            'addTag' => array(),
            'delete' => array(),
            'deleteSelection' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'disable' => array(),
            'disableTag' => array(),
            'enable' => array(),
            'index' => array('*'),
            'taxonomy_tags' => array('*'),
            'taxonomyMassConfirmation' => array('perm_tagger'),
            'taxonomyMassHide' => array('perm_tagger'),
            'taxonomyMassUnhide' => array('perm_tagger'),
            'toggleEnable' => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'toggleRequired' => array(),
            'toggleHighlighted' => array(),
            'massEnable'  => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massDisable'  => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massRequire'  => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massOptional'  => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massHighlight'  => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'massRemoveHighlight'  => array('AND' => ['perm_site_admin', 'theming_enabled']),
            'update' => array(),
            'import' => [],
            'export' => ['*'],
            'railCard' => array('*'),
            'view' => array('*'),
            'unhideTag' => array('perm_tag_editor'),
            'hideTag' => array('perm_tag_editor'),
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
            'deleteSelection' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
            'view' => ['perm_site_admin'],
            'push' => ['perm_site_admin'],
            'getRoot' => ['perm_site_admin'],
            'getCollections' => ['perm_site_admin']
        ],
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
            'change_pw' => ['AND' => ['self_management_enabled', 'password_change_enabled', 'not_read_only_authkey']],
            'checkIfLoggedIn' => array('*'),
            'discardRegistrations' => array(),
            'downloadTerms' => array('*'),
            'edit' => array('self_management_enabled'),
            'email_otp' => array('*'),
            'forgot' => ['AND' => ['password_forgotten_enabled', 'password_change_enabled']],
            'heartbeat' => ['*'],
            'ipUser' => [],
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
            'onboarding' => array('theming_enabled'),
            'onboardingSeen' => array('theming_enabled'),
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
            'updateToAdvancedAuthKeys' => array(),
            'userIp' => [],
            'verifyCertificate' => array(),
            'verifyGPG' => array(),
            'view' => array('*'),
            'viewPeriodicSummary' => ['*'],
            'getGpgPublicKey' => array('*'),
            'getSmimeCertificate' => ['*'],
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
            'deleteSelection' => array('AND' => ['not_read_only_authkey', 'theming_enabled']),
            'setHomePage' => array('not_read_only_authkey'),
            'eventIndexColumnToggle' => ['*'],
            'setTheme' => ['*'],
            'setBootstrapTheme' => ['*'],
            'setEventTemplateUserFormMode' => ['*']
        ),
        // Value Intelligence. Read-only and aggregate-only, so any role may
        // look; per-row ACL is enforced by the model calls behind each
        // panel. Gated on theming so a themes-disabled instance answers
        // 403 rather than 500 on a missing themed view.
        'values' => array(
            // The page in front of the profile, and the box on it. Same
            // reasoning as the rest of this block: read-only, and every
            // per-row ACL is enforced by the model call behind it — the
            // resolver's existence probe is `buildConditions`-scoped,
            // so it can only answer about records the reader may see.
            'index' => array('theming_enabled'),
            'resolve' => array('theming_enabled'),
            'triage' => array('theming_enabled'),
            'assess' => array('theming_enabled'),
            'matches' => array('theming_enabled'),
            'view' => array('*'),
            'viewOccurrences' => array('theming_enabled'),
            'viewReporting' => array('theming_enabled'),
            'viewContext' => array('theming_enabled'),
            'viewAnalystPreview' => array('theming_enabled'),
            'viewVerdictCard' => array('theming_enabled'),
            'viewHoverCard' => array('theming_enabled'),
            'viewHoverEnrichment' => array('theming_enabled'),
            'viewSightings' => array('theming_enabled'),
            'viewLifecycle' => array('theming_enabled'),
            'viewMatrix' => array('theming_enabled'),
            'viewGalaxyMatrix' => array('theming_enabled'),
            'viewExternal' => array('theming_enabled'),
            'viewVerdict' => array('theming_enabled'),
            'viewVerdictAside' => array('theming_enabled'),
            // The five content tabs. Listed here rather than per tab phase
            // so a tab lands as one controller-plus-element change: an
            // action missing from this list is a 403 behind a spinner that
            // never resolves, and a site admin never sees it.
            'viewOccurrenceTable' => array('theming_enabled'),
            'viewSightingChart' => array('theming_enabled'),
            'viewSightingList' => array('theming_enabled'),
            'viewRelevance' => array('theming_enabled'),
            'viewSightingReporters' => array('theming_enabled'),
            'viewSightingAdd' => array('theming_enabled'),
            'viewRelationCooccurrence' => array('theming_enabled'),
            'viewRelationDated' => array('theming_enabled'),
            'viewRelationNearMatch' => array('theming_enabled'),
            'viewRelationAsserted' => array('theming_enabled'),
            'viewRelationExternal' => array('theming_enabled'),
            'viewRelationReferences' => array('theming_enabled'),
            'viewRelationGraph' => array('theming_enabled'),
            'graph' => array('theming_enabled'),
            'graphOccurrences' => array('theming_enabled'),
            'viewRelationThreats' => array('theming_enabled'),
            'viewRelationSettings' => array('theming_enabled'),
            'viewEnrichment' => array('theming_enabled'),
            // Running a module is the one action on this page that
            // leaves the building, and MISP's own bar for querying one
            // at all is `perm_add` — both `attributes/hoverEnrichment`
            // and `events/queryEnrichment` carry it. The catalogue
            // above it stays readable to everyone: what *could* be
            // asked is not a secret, and the control renders disabled.
            'viewEnrichmentPanel' => array('theming_enabled'),
            'viewEnrichmentRun' => array(
                'AND' => array('perm_add', 'theming_enabled')
            ),
            // Same bar as the run it is: the Overview's chips are one
            // module query each, at the same endpoint's price.
            'viewEnrichmentBadge' => array(
                'AND' => array('perm_add', 'theming_enabled')
            ),
            // The Pivot Explorer's Enrich pivot: offered only to readers
            // who may run a module, stored answers included.
            'enrichmentTypes' => array(
                'AND' => array('perm_add', 'theming_enabled')
            ),
            'enrichmentStored' => array(
                'AND' => array('perm_add', 'theming_enabled')
            ),
            'enrichmentRun' => array(
                'AND' => array('perm_add', 'theming_enabled')
            ),
            'newEvent' => array(
                'AND' => array('perm_add', 'theming_enabled')
            ),
            'createEvent' => array(
                'AND' => array('perm_add', 'theming_enabled')
            ),
            'viewAnalystStanding' => array('theming_enabled'),
            'viewAnalystThread' => array('theming_enabled'),
            'viewAnalystReports' => array('theming_enabled'),
            'viewAnalystComments' => array('theming_enabled'),
            'viewTimeline' => array('theming_enabled'),
            'viewHistory' => array('theming_enabled'),
            'search' => array('*'),
            'delete' => array(),
        ),
        'warninglists' => array(
            'checkValue' => ['*'],
            'delete' => ['perm_warninglist'],
            'entries' => ['*'],
            'deleteSelection' => ['AND'=> ['perm_warninglist', 'theming_enabled']],
            'enableWarninglist' => ['perm_warninglist'],
            'massEnable' => ['AND'=> ['perm_warninglist', 'theming_enabled']],
            'massDisable' => ['AND'=> ['perm_warninglist', 'theming_enabled']],
            'getToggleField' => ['perm_warninglist'],
            'index' => array('*'),
            'railCard' => ['*'],
            'testValue' => ['*'],
            'toggleEnable' => ['AND'=> ['perm_warninglist', 'theming_enabled']],
            'update' => array(),
            'view' => array('*'),
            'edit' => ['perm_warninglist'],
            'add' => ['perm_warninglist'],
            'export' => ['*'],
            'import' => ['perm_warninglist'],
        ),
        'workflows' => [
            'add' => [],
            'adhoc' => [],
            'index' => [],
            'rebuildRedis' => [],
            'edit' => [],
            'delete' => [],
            'deleteSelection' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
            'view' => [],
            'editor' => [],
            'triggers' => [],
            'moduleIndex' => [],
            'moduleView' => [],
            'toggleModule' => [],
            'massToggleTrigger' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
            'massToggleModule' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
            'toggleDebugMode' => ['AND'=> ['perm_site_admin', 'theming_enabled']],
            'checkGraph' => [],
            'executeWorkflow' => [],
            'debugToggleField' => [],
            'massToggleField' => [],
            'moduleStatelessExecution' => [],
        ],
        'workflowBlueprints' => [
            'add' => [],
            'delete' => [],
            'deleteSelection' => [],
            'edit' => [],
            'export' => [],
            'import' => [],
            'index' => [],
            'update' => [],
            'view' => [],
        ],
        'workspaces' => [
            'active' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'addNodes' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'data' => ['*'],
            'edges' => ['*'],
            'editable' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'export' => ['*'],
            'fork' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'forTarget' => ['*'],
            'import' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'removeNodes' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'save' => ['AND' => ['perm_add', 'perm_analyst_data']],
            'thumbnail' => ['*'],
            'view' => ['*'],
        ],
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
            if (Configure::read('MISP.disable_user_add') && !$user['Role']['perm_site_admin']) {
                throw new ForbiddenException('Adding users has been disabled on this instance.');
            }
            return true;
        };
        $this->dynamicChecks['delegation_enabled'] = function (array $user) {
            return (bool)Configure::read('MISP.delegation');
        };
        // Returns true if current user is not using advanced auth key or if authkey is not read only
        $this->dynamicChecks['not_read_only_authkey'] = function (array $user) {
            return !isset($user['authkey_read_only']) || !$user['authkey_read_only'];
        };
        // Overmind is always available, whatever MISP.enable_themes says.
        $this->dynamicChecks['theming_enabled'] = function (array $user) {
            return true;
        };
        // The ACL evaluator does not nest, so an OR-ed pair used inside an AND has to be a dynamic check
        $this->dynamicChecks['perm_decaying_or_admin'] = function (array $user) {
            return (bool)($user['Role']['perm_admin'] || $user['Role']['perm_decaying']);
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
            throw new InvalidArgumentException('Passed object does not contain a GalaxyCluster.');
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
     * Checks if user can modify given galaxy cluster
     *
     * @param array $user
     * @param array $cluster
     * @return bool
     */
    public function canModifyGalaxy(array $user, array $galaxy)
    {
        if (!isset($galaxy['Galaxy'])) {
            throw new InvalidArgumentException('Passed object does not contain a Galaxy.');
        }
        if ($galaxy['Galaxy']['default']) {
            return false; // it is not possible to edit default clusters
        }
        if ($user['Role']['perm_site_admin']) {
            return true;
        }
        if (!$user['Role']['perm_galaxy_editor']) {
            return false;
        }
        return $galaxy['Galaxy']['orgc_id'] == $user['org_id'];
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


     /**
     * @param array $user
     * @param array $collection
     * @return bool
     */
    public function canModifyCollection(array $user, array $collection)
    {
        if (!isset($collection['Collection'])) {
            throw new InvalidArgumentException('Passed object does not contain a Collection.');
        }
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        if (!$user['Role']['perm_modify']) {
            return false;
        }
        return $user['org_id'] == $collection['Collection']['org_id'];
    }

     /**
     * @param array $user
     * @param array $warninglist
     * @return bool
     */
    public function canModifyWarninglist(array $user, array $warninglist)
    {
        if (!isset($warninglist['Warninglist'])) {
            throw new InvalidArgumentException('Passed object does not contain a Warninglist.');
        }
        if (!empty($user['Role']['perm_site_admin'])) {
            return true;
        }
        if (!empty($user['Role']['perm_warninglist'])) {
            return true;
        }
        return false;
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
