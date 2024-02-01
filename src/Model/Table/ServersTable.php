<?php

namespace App\Model\Table;

use App\Http\Exception\HttpSocketHttpException;
use App\Http\Exception\HttpSocketJsonException;
use App\Lib\Tools\BackgroundJobsTool;
use App\Lib\Tools\HttpTool;
use App\Lib\Tools\ProcessTool;
use App\Lib\Tools\RedisTool;
use App\Lib\Tools\ServerSyncTool;
use App\Model\Table\AppTable;
use Cake\Core\Configure;
use Cake\Validation\Validator;
use Exception;

class ServersTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior('EncryptedFields', ['fields' => ['authkey']]);
        $this->addBehavior(
            'JsonFields',
            [
                'fields' => [
                    'push_rules' => [
                        'default' => ["tags" => ["OR" => [], "NOT" => []], "orgs" => ["OR" => [], "NOT" => []]]
                    ],
                    'pull_rules' => [
                        'default' => ["tags" => ["OR" => [], "NOT" => []], "orgs" => ["OR" => [], "NOT" => []], "type_attributes" => ["NOT" => []], "type_objects" => ["NOT" => []], "url_params" => ""]
                    ]
                ],
            ]
        );

        $this->belongsTo(
            'Organisations',
            [
                'className' => 'Organisations',
                'foreignKey' => 'org_id',
                'propertyName' => 'Organisation',
            ]
        );
        $this->belongsTo(
            'RemoteOrg',
            [
                'className' => 'Organisations',
                'foreignKey' => 'remote_org_id',
                'propertyName' => 'RemoteOrg',
            ]
        );
        $this->hasMany(
            'SharingGroupServers',
            [
                'foreignKey' => 'server_id',
                'dependent' => true,
            ]
        );
        $this->hasMany(
            'Users',
            [
                'className' => 'Users',
                'foreignKey' => 'server_id',
                'dependent' => true,
            ]
        );
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('name')
            ->requirePresence(['name'], 'create')
            ->add(
                'url',
                [
                    'validateURL' => [
                        'rule' => function ($value) {
                            return $this->testURL($value);
                        }
                    ]
                ]
            )
            ->add(
                'authkey',
                [
                    'validateAuthkey' => [
                        'rule' => function ($value) {
                            return $this->validateAuthkey($value);
                        }
                    ]
                ]
            )
            ->add(
                'org_id',
                [
                    'validateOrgId' => [
                        'rule' => function ($value) {
                            return $this->valueIsID($value);
                        },
                        'allowEmpty' => false,
                        'required' => true,
                    ]
                ]
            )
            ->boolean('push')
            ->allowEmptyString('push')
            ->boolean('pull')
            ->allowEmptyString('pull')
            ->boolean('push_sightings')
            ->allowEmptyString('push_sightings')
            ->integer('lastpushedid')
            ->allowEmptyString('lastpushedid')
            ->integer('lastpulledid')
            ->allowEmptyString('lastpulledid');

        return $validator;
    }

    public function testURL($value)
    {
        // only run this check via the GUI, via the CLI it won't work
        if (!empty($value) && !preg_match('/^http(s)?:\/\//i', $value)) {
            return 'Invalid baseurl, please make sure that the protocol is set.';
        }
        if ($this->testForEmpty($value) !== true) {
            return $this->testForEmpty($value);
        }
        return true;
    }

    public function testForEmpty($value)
    {
        $value = trim($value);
        if ($value === '') {
            return 'Value not set.';
        }
        return true;
    }

    public function captureServer($server, $user)
    {
        if (isset($server[0])) {
            $server = $server[0];
        }
        if ($server['url'] == Configure::read('MISP.baseurl')) {
            return 0;
        }
        $existingServer = $this->find(
            'all',
            [
                'recursive' => -1,
                'conditions' => ['url' => $server['url']]
            ]
        )->disableHydration()->first();
        // unlike with other capture methods, if we find a server that we don't know
        // we don't want to save it.
        if (empty($existingServer)) {
            return false;
        }
        return $existingServer['id'];
    }

    public function fetchServer($id)
    {
        if (empty($id)) {
            return false;
        }
        $conditions = ['Servers.id' => $id];
        if (!is_numeric($id)) {
            $conditions = [
                'OR' => [
                    'LOWER(Servers.name)' => strtolower($id),
                    'LOWER(Servers.url)' => strtolower($id)
                ]
            ];
        }
        $server = $this->find(
            'all',
            [
                'conditions' => $conditions,
                'recursive' => -1
            ]
        )->disableHydration()->first();
        return (empty($server)) ? false : $server;
    }

    /**
     * @param int $workerIssueCount
     * @return array
     * @throws ProcessException
     */
    public function workerDiagnostics(&$workerIssueCount)
    {
        $worker_array = [
            'cache' => ['ok' => false],
            'default' => ['ok' => false],
            'email' => ['ok' => false],
            'prio' => ['ok' => false],
            'update' => ['ok' => false]
        ];

        try {
            $workers = $this->getWorkers();
        } catch (Exception $e) {
            // TODO: [3.x-MIGRATION] check exception logging in 3.x
            // $this->logException('Could not get list of workers.', $e);
            return $worker_array;
        }

        $currentUser = ProcessTool::whoami();
        $procAccessible = file_exists('/proc');
        foreach ($workers as $pid => $worker) {
            if (!is_numeric($pid)) {
                throw new Exception('Non numeric PID found.');
            }
            $entry = $worker['type'] === 'regular' ? $worker['queue'] : $worker['type'];
            $correctUser = ($currentUser === $worker['user']);
            if ($procAccessible) {
                $alive = $correctUser && file_exists("/proc/$pid");
            } else {
                $alive = 'N/A';
            }
            $ok = true;
            if (!$alive || !$correctUser) {
                $ok = false;
                $workerIssueCount++;
            }
            $worker_array[$entry]['workers'][] = [
                'pid' => $pid,
                'user' => $worker['user'],
                'alive' => $alive,
                'correct_user' => $correctUser,
                'ok' => $ok
            ];
        }
        foreach ($worker_array as $k => $queue) {
            if (isset($queue['workers'])) {
                foreach ($queue['workers'] as $worker) {
                    if ($worker['ok']) {
                        $worker_array[$k]['ok'] = true; // If at least one worker is up, the queue can be considered working
                    }
                }
            }

            $worker_array[$k]['jobCount'] = BackgroundJobsTool::getInstance()->getQueueSize($k);

            if (!isset($queue['workers'])) {
                $workerIssueCount++;
                $worker_array[$k]['ok'] = false;
            }
        }
        $worker_array['proc_accessible'] = $procAccessible;
        $worker_array['controls'] = 1;
        if (Configure::check('MISP.manage_workers')) {
            $worker_array['controls'] = Configure::read('MISP.manage_workers');
        }

        if (Configure::read('BackgroundJobs.enabled')) {
            try {
                $worker_array['supervisord_status'] = BackgroundJobsTool::getInstance()->getSupervisorStatus();
            } catch (Exception $exception) {
                $this->logException('Error getting supervisor status.', $exception);
                $worker_array['supervisord_status'] = false;
            }
        }

        return $worker_array;
    }

    /**
     * @param array $servers
     * @return array
     */
    public function attachServerCacheTimestamps(array $servers)
    {
        $redis = RedisTool::init();
        if ($redis === false) {
            return $servers;
        }
        $redis->pipeline();
        foreach ($servers as $server) {
            $redis->get('misp:server_cache_timestamp:' . $server['id']);
        }
        $results = $redis->exec();
        foreach ($servers as $k => $v) {
            $servers[$k]['cache_timestamp'] = $results[$k];
        }
        return $servers;
    }

    /**
     * @param array $server
     * @param bool $withPostTest
     * @return array
     * @throws JsonException
     */
    public function runConnectionTest(array $server, $withPostTest = true)
    {
        try {
            $clientCertificate = HttpTool::getServerClientCertificateInfo($server);
            if ($clientCertificate) {
                $clientCertificate['valid_from'] = $clientCertificate['valid_from'] ? $clientCertificate['valid_from']->format('c') : __('Not defined');
                $clientCertificate['valid_to'] = $clientCertificate['valid_to'] ? $clientCertificate['valid_to']->format('c') : __('Not defined');
                $clientCertificate['public_key_size'] = $clientCertificate['public_key_size'] ?: __('Unknown');
                $clientCertificate['public_key_type'] = $clientCertificate['public_key_type'] ?: __('Unknown');
            }
        } catch (Exception $e) {
            $clientCertificate = ['error' => $e->getMessage()];
        }

        $serverSync = new ServerSyncTool($server, $this->setupSyncRequest($server));

        try {
            $info = $serverSync->info();
            $response = [
                'status' => 1,
                'info' => $info,
                'client_certificate' => $clientCertificate,
            ];

            $connectionMeta = $serverSync->connectionMetaData();
            if (isset($connectionMeta['crypto']['protocol'])) {
                $response['tls_version'] = $connectionMeta['crypto']['protocol'];
            }
            if (isset($connectionMeta['crypto']['cipher_name'])) {
                $response['tls_cipher'] = $connectionMeta['crypto']['cipher_name'];
            }

            if ($withPostTest) {
                $response['post'] = $serverSync->isSupported(ServerSyncTool::FEATURE_POST_TEST) ? $this->runPOSTtest($serverSync) : null;
            }

            return $response;
        } catch (HttpSocketHttpException $e) {
            $response = $e->getResponse();
            if ($e->getCode() === 403) {
                return ['status' => 4, 'client_certificate' => $clientCertificate];
            } else if ($e->getCode() === 405) {
                try {
                    $responseText = $e->getResponse()->getJson()['message'];
                    if ($responseText === 'Your user account is expecting a password change, please log in via the web interface and change it before proceeding.') {
                        return ['status' => 5, 'client_certificate' => $clientCertificate];
                    } elseif ($responseText === 'You have not accepted the terms of use yet, please log in via the web interface and accept them.') {
                        return ['status' => 6, 'client_certificate' => $clientCertificate];
                    }
                } catch (Exception $e) {
                    // pass
                }
            }
        } catch (HttpSocketJsonException $e) {
            $response = $e->getResponse();
        } catch (Exception $e) {
            $logTitle = 'Error: Connection test failed. Reason: ' .  $e->getMessage();
            $this->loadLog()->createLogEntry('SYSTEM', 'error', 'Server', $server['id'], $logTitle);
            return ['status' => 2, 'client_certificate' => $clientCertificate];
        }

        $logTitle = 'Error: Connection test failed. Returned data is in the change field.';
        $this->loadLog()->createLogEntry(
            'SYSTEM',
            'error',
            'Server',
            $server['id'],
            $logTitle,
            [
                'response' => ['', $response->getStringBody()],
                'response-code' => ['', $response->getStatusCode()],
            ]
        );
        return ['status' => 3, 'client_certificate' => $clientCertificate];
    }
}
