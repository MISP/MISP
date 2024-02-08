<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\Locator\LocatorAwareTrait;

class Server extends AppModel
{
    use LocatorAwareTrait;

    public const SETTING_CRITICAL = 0,
        SETTING_RECOMMENDED = 1,
        SETTING_OPTIONAL = 2;

    public const SYNC_TEST_ERROR_CODES = [
        2 => 'Server unreachable',
        3 => 'Unexpected error',
        4 => 'Authentication failed',
        5 => 'Password change required',
        6 => 'Terms not accepted'
    ];

    public const ACTIONS_DESCRIPTIONS = [
        'verifyGnuPGkeys' => [
            'title' => 'Verify GnuPG keys',
            'description' => "Run a full validation of all GnuPG keys within this instance's userbase. The script will try to identify possible issues with each key and report back on the results.",
            'url' => '/users/verifyGPG/'
        ],
        'databaseCleanupScripts' => [
            'title' => 'Database Cleanup Scripts',
            'description' => 'If you run into an issue with an infinite upgrade loop (when upgrading from version ~2.4.50) that ends up filling your database with upgrade script log messages, run the following script.',
            'url' => '/logs/pruneUpdateLogs/'
        ],
        'releaseUpdateLock' => [
            'title' => 'Release update lock',
            'description' => 'If your your database is locked and is not updating, unlock it here.',
            'ignore_disabled' => true,
            'url' => '/servers/releaseUpdateLock/'
        ],
        'normalizeCustomTagsToTaxonomyFormat' => [
            'title' => 'Normalize custom tags to taxonomy format',
            'description' => 'Transform all custom tags existing in a taxonomy into the taxonomy version',
            'url' => '/taxonomies/normalizeCustomTagsToTaxonomyFormat/'
        ],
    ];

    // TODO: [3.x-MIGRATION] Move the usage to each individual command help
    private function generateCommandLineFunctions()
    {
        return [
            'console_admin_tasks' => [
                'data' => [
                    'Get setting' => 'MISP/app/Console/cake Admin getSetting [setting|all]',
                    'Set setting' => 'MISP/app/Console/cake Admin setSetting [setting] [value]',
                    'Get authkey' => 'MISP/app/Console/cake Admin getAuthkey [user_email]',
                    'Change authkey' => 'MISP/app/Console/cake Admin change_authkey [user_email] [authkey]',
                    'Set baseurl' => 'MISP/app/Console/cake Admin setSetting MISP.baseurl [baseurl]',
                    'Change password' => 'MISP/app/Console/cake User change_pw [email] [new_password] [--no_password_change]',
                    'Clear Bruteforce entries' => 'MISP/app/Console/cake Admin clearBruteforce [user_email]',
                    'Clean caches' => 'MISP/app/Console/cake Admin cleanCaches',
                    'Set database version' => 'MISP/app/Console/cake Admin setDatabaseVersion [version]',
                    'Run database update' => 'MISP/app/Console/cake Admin updateDatabase',
                    'Run updates' => 'MISP/app/Console/cake Admin runUpdates',
                    'Update all JSON structures' => 'MISP/app/Console/cake Admin updateJSON',
                    'Update Galaxy definitions' => 'MISP/app/Console/cake Admin updateGalaxies',
                    'Update taxonomy definitions' => 'MISP/app/Console/cake Admin updateTaxonomies',
                    'Update object templates' => 'MISP/app/Console/cake Admin updateObjectTemplates [user_id]',
                    'Update Warninglists' => 'MISP/app/Console/cake Admin updateWarningLists',
                    'Update Noticelists' => 'MISP/app/Console/cake Admin updateNoticeLists',
                    'Set default role' => 'MISP/app/Console/cake Admin setDefaultRole [role_id]',
                    'Get IPs for user ID' => 'MISP/app/Console/cake Admin UserIP [user_id]',
                    'Get user ID for user IP' => 'MISP/app/Console/cake Admin IPUser [ip]',
                    'Generate correlation' => 'MISP/app/Console/cake Admin jobGenerateCorrelation [job_id]',
                    'Truncate correlation table' => 'MISP/app/Console/cake Admin truncateTable [user_id] [correlation_engine_name] [job_id]',
                    'Purge correlation' => 'MISP/app/Console/cake Admin jobPurgeCorrelation [job_id]',
                    'Generate shadow attribute correlation' => 'MISP/app/Console/cake Admin jobGenerateShadowAttributeCorrelation [job_id]',
                    'Update MISP' => 'MISP/app/Console/cake Admin updateMISP',
                    'Update after pull' => 'MISP/app/Console/cake Admin updateAfterPull [submodule_name] [job_id] [user_id]',
                    'Job upgrade' => 'MISP/app/Console/cake Admin jobUpgrade24 [job_id] [user_id]',
                    'Prune update logs' => 'MISP/app/Console/cake Admin prune_update_logs [job_id] [user_id]',
                    'Recover since last successful update' => 'MISP/app/Console/cake Admin recoverSinceLastSuccessfulUpdate',
                    'Reset sync authkeys' => 'MISP/app/Console/cake Admin resetSyncAuthkeys [user_id]',
                    'Purge feed events' => 'MISP/app/Console/cake Admin purgeFeedEvents [user_id] [feed_id]',
                    'Dump current database schema' => 'MISP/app/Console/cake Admin dumpCurrentDatabaseSchema',
                    'Scan attachment' => 'MISP/app/Console/cake Admin scanAttachment [input] [attribute_id] [job_id]',
                    'Clean excluded correlations' => 'MISP/app/Console/cake Admin cleanExcludedCorrelations [job_id]',
                ],
                'description' => __('Certain administrative tasks are exposed to the API, these help with maintaining and configuring MISP in an automated way / via external tools.'),
                'header' => __('Administering MISP via the CLI')
            ],
            'console_automation_tasks' => [
                'data' => [
                    'PullAll' => 'MISP/app/Console/cake Server pullAll [user_id] [full|update]',
                    'Pull' => 'MISP/app/Console/cake Server pull [user_id] [server_id] [full|update]',
                    'PushAll' => 'MISP/app/Console/cake Server pushAll [user_id]',
                    'Push' => 'MISP/app/Console/cake Server push [user_id] [server_id]',
                    'Cache server' => 'MISP/app/Console/cake server cacheServer [user_id] [server_id]',
                    'Cache all servers' => 'MISP/app/Console/cake server cacheServerAll [user_id]',
                    'List all feeds' => 'MISP/app/Console/cake Server listFeeds [json|table]',
                    'View feed' => 'MISP/app/Console/cake Server viewFeed [feed_id] [json|table]',
                    'Toggle feed fetching' => 'MISP/app/Console/cake Server toggleFeed [feed_id]',
                    'Toggle feed caching' => 'MISP/app/Console/cake Server toggleFeedCaching [feed_id]',
                    'Load default feed configurations' => 'MISP/app/Console/cake Server loadDefaultFeeds [feed_id]',
                    'Cache feeds for quick lookups' => 'MISP/app/Console/cake Server cacheFeed [user_id] [feed_id|all|csv|text|misp]',
                    'Fetch feeds as local data' => 'MISP/app/Console/cake Server fetchFeed [user_id] [feed_id|all|csv|text|misp]',
                    'Run enrichment' => 'MISP/app/Console/cake Event enrichment [user_id] [event_id] [json_encoded_module_list]',
                    'Test' => 'MISP/app/Console/cake Server test [server_id]',
                    'List' => 'MISP/app/Console/cake Server list',
                    'Enqueue pull' => 'MISP/app/Console/cake Server enqueuePull [timestamp] [user_id] [task_id]',
                    'Enqueue push' => 'MISP/app/Console/cake Server enqueuePush [timestamp] [task_id] [user_id]',
                    'Enqueue feed fetch' => 'MISP/app/Console/cake Server enqueueFeedFetch [timestamp] [user_id] [task_id]',
                    'Enqueue feed cache' => 'MISP/app/Console/cake Server enqueueFeedCache [timestamp] [user_id] [task_id]',
                    'Update sharing groups based on blueprints' => 'MISP/app/Console/cake Server executeSGBlueprint [blueprint_id|all|attached|detached]'
                ],
                'description' => __('If you would like to automate tasks such as caching feeds or pulling from server instances, you can do it using the following command line tools. Simply execute the given commands via the command line / create cron jobs easily out of them.'),
                'header' => __('Automating certain console tasks')
            ],
            'event_management_tasks' => [
                'data' => [
                    'Publish event' => 'MISP/app/Console/cake Event publish [event_id] [pass_along] [job_id] [user_id]',
                    'Publish sightings' => 'MISP/app/Console/cake Event publish_sightings [event_id] [pass_along] [job_id] [user_id]',
                    'Publish Galaxy clusters' => 'MISP/app/Console/cake Event publish_galaxy_clusters [cluster_id] [job_id] [user_id] [pass_along]',
                    'Cache event' => 'MISP/app/Console/cake Event cache [user_id] [event_id] [export_type]',
                    'Cache bro' => 'MISP/app/Console/cake Event cachebro [user_id] [event_id]',
                    'Recover event' => 'MISP/app/Console/cake Event recoverEvent [job_id] [event_id]',
                    'Alert email' => 'MISP/app/Console/cake Event alertemail [user_id] [job_id] [event_id] [old_publish]',
                    'Contact email' => 'MISP/app/Console/cake Event contactemail [event_id] [message] [all] [user_id] [process_id]',
                    'Posts email' => 'MISP/app/Console/cake Event postsemail [user_id] [post_id] [event_id] [title] [message] [process_id]',
                    'Enqueue caching' => 'MISP/app/Console/cake Event enqueueCaching [timestamp]',
                    'Do publish' => 'MISP/app/Console/cake Event doPublish [event_id]',
                    'Run enrichment' => 'MISP/app/Console/cake Event enrichment [user_id] [event_id] [json_encoded_module_list]',
                    'Process free text' => 'MISP/app/Console/cake Event processfreetext [input]',
                    'Process module result' => 'MISP/app/Console/cake Event processmoduleresult [input]',
                ],
                'description' => __('The events can be managed via the CLI in addition to the UI / API management tools'),
                'header' => __('Managing the events')
            ],
            'worker_management_tasks' => [
                'data' => [
                    'Get list of workers' => 'MISP/app/Console/cake Admin getWorkers [all|dead]',
                    'Start a worker' => 'MISP/app/Console/cake Admin startWorker [queue_name]',
                    'Restart a worker' => 'MISP/app/Console/cake Admin restartWorker [worker_pid]',
                    'Restart all workers' => 'MISP/app/Console/cake Admin restartWorkers',
                    'Kill a worker' => 'MISP/app/Console/cake Admin killWorker [worker_pid]',
                ],
                'description' => __('The background workers can be managed via the CLI in addition to the UI / API management tools'),
                'header' => __('Managing the background workers')
            ]
        ];
    }

    private function loadLocalOrganisations($strict = false)
    {
        static $localOrgs;

        if ($localOrgs === null) {
            $localOrgs = $this->Organisation->find(
                'list',
                [
                    'conditions' => ['local' => 1],
                    'recursive' => -1,
                    'fields' => ['Organisation.id', 'Organisation.name']
                ]
            );
        }

        if (!$strict) {
            return array_replace([0 => __('No organisation selected.')], $localOrgs);
        }

        return $localOrgs;
    }

    public function loadAvailableLanguages()
    {
        $dirs = glob(APP . 'Locale/*', GLOB_ONLYDIR);
        $languages = ['eng' => 'eng'];
        foreach ($dirs as $dir) {
            $dir = str_replace(APP . 'Locale' . DS, '', $dir);
            $languages[$dir] = $dir;
        }
        return $languages;
    }

    public function loadTagCollections()
    {
        $this->TagCollection = $this->fetchTable('TagCollections');
        $user = ['Role' => ['perm_site_admin' => 1]];
        $tagCollections = $this->TagCollection->fetchTagCollection($user);
        $options = [0 => 'None'];
        foreach ($tagCollections as $tagCollection) {
            $options[intval($tagCollection['TagCollection']['id'])] = $tagCollection['TagCollection']['name'];
        }
        return $options;
    }
}
