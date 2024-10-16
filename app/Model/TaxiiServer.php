<?php
App::uses('AppModel', 'Model');
App::uses('EncryptedValue', 'Tools');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('RandomTool', 'Tools');
App::uses('JSONConverterTool', 'Tools');
App::uses('JsonTool', 'Tools');

class TaxiiServer extends AppModel
{
    public $actsAs = [
        'AuditLog',
        'SysLogLogable.SysLogLogable' => [
            'roleModel' => 'Role',
            'roleKey' => 'role_id',
            'change' => 'full'
        ],
        'Containable'
    ];

    private $Job = null;
    private $Event = null;
    private $Allowedlist = null;

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->id) && empty($this->data['TaxiiServer']['uuid'])) {
            $this->data['TaxiiServer']['uuid'] = CakeText::uuid();
        }
        return true;
    }

    public function pushRouter($id, $user)
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob($user, Job::WORKER_DEFAULT, 'push_taxii', "Taxii Server ID: $id", 'Pushing.');

            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_SERVER,
                [
                    'push_taxii',
                    $user['id'],
                    $id,
                    $jobId
                ],
                true,
                $jobId
            );
        }

        return $this->push($id, $user);
    }

    public function push($id, $user, $jobId = null)
    {
        $this->Event = ClassRegistry::init('Event');
        $this->Job = ClassRegistry::init('Job');
        $taxii_server = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['TaxiiServer.id' => $id]
        ]);
        $filters = $this->__setPushFilters($taxii_server);
        $elementCounter = 0;
        $eventid = $this->Event->filterEventIds($user, $filters, $elementCounter);
        $eventCount = count($eventid);

        $attribute_coefficient = Configure::check('MISP.default_attribute_memory_coefficient') ? Configure::read('MISP.default_attribute_memory_coefficient') : 80;

        $exportTool = ['memory_scaling_factor' => $attribute_coefficient];
        $eventids_chunked = $this->Event->clusterEventIds($exportTool, $eventid);
        $i = 1;
        $this->Allowedlist = ClassRegistry::init('Allowedlist');
        foreach ($eventids_chunked as $eventids) {
            $this->__pushEvents($user, $taxii_server, $filters, $eventids, $i, $jobId, $eventCount);
        }
        unset($eventid);
        return true;
    }

    private function __setPushFilters($taxii_server)
    {
        $filters = empty($taxii_server['TaxiiServer']['filters']) ? [] : json_decode($taxii_server['TaxiiServer']['filters'], true);
        $filters['include_attribute_count'] = 1;
        return $filters;
    }

    private function __pushEvents($user, $taxii_server, $filters, $eventids, &$i, $jobId = null, $eventCount)
    {
        $filters['eventid'] = $eventids;
        if (!empty($filters['tags']['NOT'])) {
            $filters['blockedAttributeTags'] = $filters['tags']['NOT'];
            unset($filters['tags']['NOT']);
        }
        $result = $this->Event->fetchEvent($user, $filters, true);
        
        $result = $this->Allowedlist->removeAllowedlistedFromArray($result, false);
        $temporaryFolder = $this->temporaryFolder();
        $temporaryFolderPath = $temporaryFolder['dir']->path;
        $this->Job->id = $jobId;
        foreach ($result as $event) {
            $temporaryFile = $this->temporaryFile($temporaryFolderPath);
            $temporaryFile->write(
                JsonTool::encode(
                    JSONConverterTool::convert($event, false, true)
                )
            );
            $temporaryFile->close();
            if ($jobId && $i % 10 == 0) {
                $this->Job->saveField('progress', intval((100 * $i) / $eventCount));
                $this->Job->saveField('message', 'Pushing Event ' . $i . '/' . $eventCount . '.');
            }
            $i++;
        }
        // execute python script here!!!
        $scriptFile = APP . 'files/scripts/taxii/taxii_push.py';
        $command = [
            ProcessTool::pythonBin(),
            $scriptFile,
            '--dir', $temporaryFolder['dir']->path,
            '--baseurl',  $taxii_server['TaxiiServer']['baseurl'],
            '--api_root', $taxii_server['TaxiiServer']['api_root'],
            '--key', $taxii_server['TaxiiServer']['api_key'],
            '--collection', $taxii_server['TaxiiServer']['collection']
        ];
        $result = ProcessTool::execute($command, null, true);
        $temporaryFolder['dir']->delete();
        if ($jobId) {
            $this->Job->saveField('progress', 100);
            $this->Job->saveField('message', 'Done, pushed ' . $i . ' events to TAXII server.');
        }
    }

    private function temporaryFolder()
    {
        $tmpDir = Configure::check('MISP.tmpdir') ? Configure::read('MISP.tmpdir') : '/tmp';
        $random = RandomTool::random_str(true, 12);
        $dir = new Folder($tmpDir . '/Taxii/' . $random, true);
        return [
            'random' => $random,
            'dir' => $dir
        ];
    }

    private function temporaryFile($temporaryFolder)
    {
        $random = RandomTool::random_str(true, 12);
        return new File($temporaryFolder . '/' . $random . '.json', true, 0644);
    }

    public function queryInstance($options)
    {
        $url = $options['TaxiiServer']['baseurl'] . $options['TaxiiServer']['uri'];
        App::uses('HttpSocket', 'Network/Http');
        $HttpSocket = new HttpSocket();
        $request = [
            'header' => [
                'Accept' => 'application/taxii+json;version=2.1',
                'Content-type' => 'application/taxii+json;version=2.1'
            ]
        ];
        if (!empty($options['TaxiiServer']['api_key'])) {
            $request['header']['Authorization'] = 'basic ' . $options['TaxiiServer']['api_key'];
        }
        try {
            if (!empty($options['type']) && $options['type'] === 'post') {
                $response = $HttpSocket->post($url, json_encode($options['body']), $request);
            } else {
                if (empty($options['query'])) {
                    $options['query'] = null;
                }
                $response = $HttpSocket->get(
                    $url,
                    $options['query'],
                    $request
                );
            }
            if ($response->isOk()) {
                return json_decode($response->body, true);
            }
        } catch (SocketException $e) {
            throw new BadRequestException(__('Something went wrong. Error returned: %s', $e->getMessage()));
        }
        if ($response->code === 403 || $response->code === 401) {
            throw new ForbiddenException(__('Authentication failed.'));
        }
        throw new BadRequestException(__('Something went wrong with the request or the remote side is having issues.'));
    }

    public function getCollections($id)
    {
        $taxii_server = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['TaxiiServer.id' => $id]
        ]);
        $taxii_server['TaxiiServer']['uri'] = '/' . $taxii_server['TaxiiServer']['api_root'] . '/collections/';
        $response = $this->queryInstance([
            'TaxiiServer' => $taxii_server['TaxiiServer'],
            'type' => 'get'
        ]);
        if (empty($response['collections'])) {
            throw new BadRequestException(__('No collections found.'));
        }
        return $response['collections'];
    }

    public function getObjects($id, $collection_id = null, $next = null)
    {
        $taxii_server = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['TaxiiServer.id' => $id]
        ]);
        if (empty($collection_id)) {
            $collection_id = $taxii_server['TaxiiServer']['collection'];
        }
        $taxii_server['TaxiiServer']['uri'] = '/' . $taxii_server['TaxiiServer']['api_root'] . '/collections/' . $collection_id . '/objects/';
        $response = $this->queryInstance([
            'TaxiiServer' => $taxii_server['TaxiiServer'],
            'type' => 'get',
            'query' => [
                'limit' => 50,
                'next' => $next
            ]
        ]);
        if (empty($response['objects'])) {
            throw new BadRequestException(__('No objects found in collection with the given query parameters.'));
        }
        return $response;
    }

    public function getObject($id, $server_id, $collection_id)
    {
        $taxii_server = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['TaxiiServer.id' => $server_id]
        ]);
        $taxii_server['TaxiiServer']['uri'] = '/' . $taxii_server['TaxiiServer']['api_root'] . '/collections/' . $collection_id . '/objects/' . $id . '/';
        $response = $this->queryInstance([
            'TaxiiServer' => $taxii_server['TaxiiServer'],
            'type' => 'get'
        ]);
        if (empty($response['objects'])) {
            throw new BadRequestException(__('Invalid object or object not found in the given collection.'));
        }
        return $response['objects'][0];
    }
}
