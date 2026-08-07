<?php

class OvermindPages
{
    /**
     * Actions rendered with the BS5 chrome, grouped by controller.
     *
     * @var array
     */
    private static $pages = array(
        // Events and their content
        'events' => array(
            'index', 'add', 'edit', 'delete', 'view', 'view2',
            'importChoice', 'automation', 'export', 'getEventInfoById',
            'freeTextImport', 'proposalEventIndex'
        ),
        'attributes' => array(
            'index', 'add', 'edit', 'delete', 'add_attachment'
        ),
        'shadow_attributes' => array('index'),
        'event_delegations' => array('index'),
        'objects' => array('add', 'edit', 'delete'),
        'sightings' => array('advanced'),
        'event_reports' => array('index', 'view', 'add', 'edit'),
        'EventReportTemplateVariables' => array('index', 'add', 'edit'),
        'collections' => array('index', 'view', 'add', 'edit'),
        'CollectionElements' => array('add', 'index'),
        'analystData' => array(
            'index', 'add', 'edit', 'view', 'delete', 'deleteSelection'
        ),

        // Taxonomy, galaxies and templates
        'tags' => array('index', 'add', 'edit', 'viewGraph'),
        'tagCollections' => array('index', 'addWithTags', 'editWithTags'),
        'taxonomies' => array(
            'index', 'delete', 'view', 'addTag', 'disableTag'
        ),
        'galaxies' => array(
            'index', 'view', 'add', 'edit', 'delete', 'viewGraph', 'export'
        ),
        'galaxy_clusters' => array(
            'index', 'view', 'add', 'edit', 'delete',
            'export_for_misp_galaxy'
        ),
        'galaxy_cluster_relations' => array('index'),
        'templates' => array('index', 'delete', 'add', 'view'),
        'templateElements' => array('delete', 'addV2', 'editV2'),
        'objectTemplates' => array('index', 'delete', 'add', 'view'),
        'object_relationships' => array('index', 'delete', 'add', 'edit'),
        'event_templates' => array(
            'index', 'view', 'import', 'instantiate', 'add', 'edit',
            'preview', 'update', 'library_status'
        ),
        'decayingModel' => array('index', 'view', 'add', 'edit', 'import'),

        // Lists and correlation
        'warninglists' => array('index', 'view', 'add', 'edit'),
        'noticelists' => array('index', 'view'),
        'regexp' => array('admin_index', 'index', 'admin_add'),
        'allowedlists' => array('admin_index', 'index', 'admin_add'),
        'correlations' => array('top', 'overCorrelations'),
        'correlation_exclusions' => array('index', 'add'),
        'correlationRules' => array(
            'index', 'add', 'edit', 'delete', 'deleteSelection',
            'executeRule'
        ),

        // Workflows
        'workflows' => array(
            'index', 'triggers', 'adhoc', 'add', 'edit', 'executeWorkflow',
            'moduleIndex', 'editor', 'massToggleTrigger',
            'massToggleModule', 'toggleDebugMode'
        ),
        'workflowBlueprints' => array(
            'index', 'import', 'add', 'edit', 'view', 'delete',
            'deleteSelection'
        ),

        // Users, roles and organisations
        'users' => array(
            // The first four are the chrome-less pages, see $authActions.
            'login', 'register', 'forgot', 'change_pw',
            'view', 'admin_view', 'admin_index', 'edit', 'admin_edit',
            'admin_add', 'admin_quickEmail', 'admin_email', 'totp_new',
            'view_login_history', 'registrations'
        ),
        'auth_keys' => array('index', 'add', 'edit', 'view'),
        'user_settings' => array('index', 'setSetting', 'deleteSelection'),
        'userLoginProfiles' => array('index'),
        'roles' => array('index', 'view', 'admin_add', 'admin_edit'),
        'organisations' => array('index', 'view', 'admin_add', 'admin_edit'),

        // Blocklists
        'eventBlocklists' => array(
            'index', 'add', 'edit', 'deleteSelection'
        ),
        'orgBlocklists' => array('index', 'add', 'edit', 'deleteSelection'),
        'galaxyClusterBlocklists' => array(
            'index', 'add', 'edit', 'deleteSelection'
        ),
        'sightingBlocklists' => array(
            'index', 'add', 'edit', 'deleteSelection'
        ),
        'analystDataBlocklists' => array(
            'index', 'add', 'edit', 'deleteSelection'
        ),

        // Synchronisation
        'servers' => array(
            'index', 'add', 'edit', 'delete', 'previewIndex',
            'previewEvent', 'pullSelectedEvents', 'idTranslator',
            'serverSettings'
        ),
        'feeds' => array(
            'index', 'add', 'edit', 'view', 'importFeeds',
            'deleteSelection', 'previewIndex', 'previewEvent',
            'getSelectedEvents', 'fetchSelectedFeeds'
        ),
        'taxiiServers' => array(
            'index', 'add', 'edit', 'delete', 'view', 'collectionsIndex',
            'objectsIndex'
        ),
        'cerebrates' => array(
            'index', 'add', 'edit', 'delete', 'view', 'pull_sgs',
            'pull_orgs'
        ),
        'communities' => array('index', 'view', 'requestAccess'),
        'sightingdb' => array('index', 'add', 'edit', 'delete'),
        'SharingGroups' => array('index', 'add', 'edit', 'delete', 'view'),
        'SharingGroupBlueprints' => array(
            'index', 'add', 'edit', 'delete', 'view', 'detach', 'execute',
            'encodeSyncRule'
        ),

        // Administration and diagnostics
        'logs' => array('index', 'admin_index'),
        'audit_logs' => array('admin_index'),
        'access_logs' => array('admin_index'),
        'benchmarks' => array('index'),
        'jobs' => array('index'),
        'tasks' => array('index', 'add', 'edit'),
        'news' => array(
            'admin_index', 'add', 'edit', 'delete', 'deleteSelection'
        ),
        'bookmarks' => array(
            'index', 'add', 'edit', 'view', 'delete', 'deleteSelection'
        ),
        'api' => array('openapi', 'rest'),
        // One entry covers every documentation page, including the
        // administration ones — they all route through Pages::display().
        'pages' => array('display'),
    );

    /**
     * Pre-authentication pages that own the whole viewport: no navbar, no
     * footer, no header strip — just the centered card over the gradient
     * background (styled in mainOvermind.css off the body data-action attr).
     *
     * Every action listed here must also appear under 'users' above.
     *
     * @var array
     */
    private static $authActions = array(
        'login', 'register', 'forgot', 'change_pw'
    );

    /**
     * Normalised controller => action => true, built on first lookup.
     *
     * @var array|null
     */
    private static $lookup = null;

    /**
     * Normalised auth action => true, built on first lookup.
     *
     * @var array|null
     */
    private static $authLookup = null;

    /**
     * Collapse every URL casing of a controller or action to one key.
     *
     * @param string $value
     * @return string
     */
    public static function normalise($value)
    {
        return strtolower(str_replace('_', '', (string)$value));
    }

    /**
     * Is this controller/action rendered with the BS5 chrome?
     *
     * @param string $controller
     * @param string $action
     * @return bool
     */
    public static function isMigrated($controller, $action)
    {
        if (self::$lookup === null) {
            self::$lookup = array();
            foreach (self::$pages as $ctrl => $actions) {
                $key = self::normalise($ctrl);
                foreach ($actions as $act) {
                    self::$lookup[$key][self::normalise($act)] = true;
                }
            }
        }
        $ctrl = self::normalise($controller);
        return isset(self::$lookup[$ctrl][self::normalise($action)]);
    }

    /**
     * Is this controller/action one of the chrome-less auth pages?
     *
     * @param string $controller
     * @param string $action
     * @return bool
     */
    public static function isAuthPage($controller, $action)
    {
        if (self::normalise($controller) !== 'users') {
            return false;
        }
        if (self::$authLookup === null) {
            self::$authLookup = array();
            foreach (self::$authActions as $act) {
                self::$authLookup[self::normalise($act)] = true;
            }
        }
        return isset(self::$authLookup[self::normalise($action)]);
    }
}
