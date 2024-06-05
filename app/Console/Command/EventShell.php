<?php
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('FileAccessTool', 'Tools');
require_once 'AppShell.php';

/**
 * @property User $User
 * @property Event $Event
 * @property Job $Job
 * @property Tag $Tag
 * @property Server $Server
 * @property Correlation $Correlation
 */
class EventShell extends AppShell
{
    public $uses = array('Event', 'Post', 'Attribute', 'Job', 'User', 'Task', 'Allowedlist', 'Server', 'Organisation', 'Correlation', 'Tag');

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('import', array(
            'help' => __('Import event from file into MISP.'),
            'parser' => array(
                'arguments' => array(
                    'user_id' => ['help' => __('User ID that will owner of uploaded event.'), 'required' => true],
                    'file' => ['help' => __('Path to JSON MISP file, can be gzipped or bz2 compressed.'), 'required' => true],
                ),
                'options' => [
                    'take-ownership' => ['boolean' => true],
                    'publish' => ['boolean' => true],
                ],
            )
        ));
        $parser->addSubcommand('testEventNotificationEmail', [
            'help' => __('Generate event notification email in EML format.'),
            'parser' => [
                'arguments' => [
                    'event_id' => ['help' => __('Event ID'), 'required' => true],
                    'user_id' => ['help' => __('User ID'), 'required' => true],
                ],
                'options' => [
                    'send' => ['help' => __('Send email to given user'), 'boolean' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('duplicateTags', [
            'help' => __('Show duplicate tags'),
        ]);
        $parser->addSubcommand('generateTopCorrelations', [
            'help' => __('Generate top correlations'),
        ]);
        $parser->addSubcommand('mergeTags', [
            'help' => __('Merge tags'),
            'parser' => [
                'arguments' => [
                    'source' => ['help' => __('Source tag ID or name. Source tag will be deleted.'), 'required' => true],
                    'destination' => ['help' => __('Destination tag ID or name.'), 'required' => true],
                ],
            ],
        ]);
        $parser->addSubcommand('reportValidationIssuesAttributes', [
            'help' => __('Report validation issues on attributes'),
        ]);
        $parser->addSubcommand('normalizeIpAddress', [
            'help' => __('Normalize IP address format in old events'),
            'parser' => [
                'options' => [
                    'dry-run' => ['help' => __('Just show what changes will be made.'), 'boolean' => true],
                ],
            ],
        ]);
        return $parser;
    }

    public function import()
    {
        list($userId, $path) = $this->args;
        $user = $this->getUser($userId);

        if (!file_exists($path)) {
            $this->error("File '$path' does not exist.");
        }
        if (!is_readable($path)) {
            $this->error("File '$path' is not readable.");
        }

        $pathInfo = pathinfo($path);
        if ($pathInfo['extension'] === 'gz') {
            $content = file_get_contents("compress.zlib://$path");
            $extension = pathinfo($pathInfo['filename'], PATHINFO_EXTENSION);
        } else if ($pathInfo['extension'] === 'bz2') {
            $content = file_get_contents("compress.bzip2://$path");
            $extension = pathinfo($pathInfo['filename'], PATHINFO_EXTENSION);
        } else {
            $content = file_get_contents($path);
            $extension = $pathInfo['extension'];
        }

        if ($content === false) {
            $this->error("Could not read content from '$path'.");
        }

        $isXml = $extension === 'xml';
        $takeOwnership = $this->params['take-ownership'];
        $publish = $this->params['publish'];
        $results = $this->Event->addMISPExportFile($user, $content, $isXml, $takeOwnership, $publish);

        foreach ($results as $result) {
            if (is_numeric($result['result'])) {
                $this->out("Event `{$result['info']}` already exists at ({$result['result']}).");
            } else if ($result['result'] === true) {
                $this->out("Event #{$result['id']}: {$result['info']} imported.");
            } else {
                $this->out("Could not import event because of validation errors: " . json_encode($result['validationIssues']));
            }
        }
    }

    public function mergeTags()
    {
        list($source, $destination) = $this->args;
        $output = $this->Tag->mergeTag($source, $destination);
        $this->out("Merged tag `{$output['source_tag']['Tag']['name']}` into `{$output['destination_tag']['Tag']['name']}`");
        $this->out(__("%s attribute or event tags changed", $output['changed']));
    }

    public function duplicateTags()
    {
        $output = $this->Tag->duplicateTags();
        $this->out($this->json($output));
    }

    public function doPublish()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Do publish'] . PHP_EOL);
        }

        $id = $this->args[0];
        $this->Event->id = $id;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid event'));
        }
        $this->Job->create();
        $data = array(
            'worker' => 'default',
            'job_type' => 'doPublish',
            'job_input' => $id,
            'status' => 0,
            'retries' => 0,
            'org' => 0,
            'message' => 'Job created.',
        );
        $this->Job->save($data);
        // update the event and set the from field to the current instance's organisation from the bootstrap. We also need to save id and info for the logs.
        $this->Event->recursive = -1;
        $event = $this->Event->read(null, $id);
        $event['Event']['published'] = 1;
        $fieldList = array('published', 'id', 'info');
        $this->Event->save($event, array('fieldList' => $fieldList));
        // only allow form submit CSRF protection.
        $this->Job->save([
            'status' => Job::STATUS_COMPLETED,
            'message' => 'Job done.'
        ]);
    }

    public function correlateValue()
    {
        $value = $this->args[0];

        if (!empty($this->args[1])) {
            $this->Job->id = intval($this->args[1]);
        } else {
            $this->Job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'correlateValue',
                $value,
                'Job created.'
            );
        }

        $this->Correlation->correlateValue($value, $this->Job->id);
        $this->Job->save([
            'status' => Job::STATUS_COMPLETED,
            'message' => 'Job done.',
            'progress' => 100
        ]);
    }

    public function cache()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Cache event'] . PHP_EOL);
        }

        $timeStart = time();
        $userId = $this->args[0];
        $id = $this->args[1];
        $user = $this->getUser($userId);
        $this->Job->id = $id;
        $export_type = $this->args[2];
        file_put_contents('/tmp/test', $export_type);
        $exportTypes = $this->Event->exportTypes();
        $typeData = $exportTypes[$export_type];
        if (!in_array($export_type, array_keys($exportTypes))) {
            $this->Job->saveField('progress', 100);
            $timeDelta = (time()-$timeStart);
            $this->Job->saveField('message', 'Job Failed due to invalid export format. (in '.$timeDelta.'s)');
            $this->Job->saveField('date_modified', date("Y-m-d H:i:s"));
            return false;
        }
        if ($export_type == 'text') {
            $types = array_keys($this->Attribute->typeDefinitions);
            $typeCount = count($types);
            foreach ($types as $k => $type) {
                $typeData['params']['type'] = $type;
                $this->__runCaching($user, $typeData, false, $export_type, '_' . $type);
                $this->Job->saveField('message', 'Processing all attributes of type '. $type . '.');
                $this->Job->saveField('progress', intval($k / $typeCount));
            }
        } else {
            $this->__runCaching($user, $typeData, $id, $export_type);
        }
        $this->Job->saveField('progress', 100);
        $timeDelta = (time()-$timeStart);
        $this->Job->saveField('message', 'Job done. (in '.$timeDelta.'s)');
        $this->Job->saveField('date_modified', date("Y-m-d H:i:s"));
    }

    private function __runCaching($user, $typeData, $id, $export_type, $subType = '')
    {
        $export_type = strtolower($typeData['type']);
        $final = $this->{$typeData['scope']}->restSearch($user, $typeData['params']['returnFormat'], $typeData['params'], false, $id);
        $dir = new Folder(APP . 'tmp/cached_exports/' . $export_type, true, 0750);
        //echo PHP_EOL . $dir->pwd() . DS . 'misp.' . $export_type . $subType . '.ADMIN' . $typeData['extension'] . PHP_EOL;
        if ($user['Role']['perm_site_admin']) {
            $file = new File($dir->pwd() . DS . 'misp.' . $export_type . $subType . '.ADMIN' . $typeData['extension']);
        } else {
            $file = new File($dir->pwd() . DS . 'misp.' . $export_type . $subType . '.' . $user['Organisation']['name'] .  $typeData['extension']);
        }
        $file->write($final);
        $file->close();
        return true;
    }

    public function cachebro()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Cache bro'] . PHP_EOL);
        }

        $timeStart = time();
        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $id = $this->args[1];
        $this->Job->id = $id;
        $this->Job->saveField('progress', 1);
        App::uses('BroExport', 'Export');
        $export = new BroExport();
        $types = array_keys($export->mispTypes);
        $typeCount = count($types);
        $dir = new Folder(APP . DS . '/tmp/cached_exports/bro', true, 0750);
        if ($user['Role']['perm_site_admin']) {
            $file = new File($dir->pwd() . DS . 'misp.bro.ADMIN.intel');
        } else {
            $file = new File($dir->pwd() . DS . 'misp.bro.' . $user['Organisation']['name'] . '.intel');
        }

        $file->write('');
        $skipHeader = false;
        foreach ($types as $k => $type) {
            $final = $this->Attribute->bro($user, $type, false, false, false, false, false, false, $skipHeader);
            $skipHeader = true;
            foreach ($final as $attribute) {
                $file->append($attribute . PHP_EOL);
            }
            $this->Job->saveField('progress', $k / $typeCount * 100);
        }
        $file->close();
        $timeDelta = (time()-$timeStart);
        $this->Job->saveField('progress', 100);
        $this->Job->saveField('message', 'Job done. (in '.$timeDelta.'s)');
        $this->Job->saveField('date_modified', date("Y-m-d H:i:s"));
    }

    public function alertemail()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Alert email'] . PHP_EOL);
        }

        $userId = $this->args[0];
        $jobId = $this->args[1];
        $eventId = $this->args[2];
        $oldpublish = isset($this->args[3]) ? $this->args[3] : null;
        $user = $this->getUser($userId);
        $this->Event->sendAlertEmail($eventId, $user, $oldpublish, $jobId);
    }

    public function contactemail()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || !isset($this->args[2]) ||
            empty($this->args[3]) || empty($this->args[4])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Contact email'] . PHP_EOL);
        }

        $id = $this->args[0];
        $message = $this->args[1];
        $all = $this->args[2];
        $userId = $this->args[3];
        $jobId = $this->args[4];

        $user = $this->getUser($userId);
        $result = $this->Event->sendContactEmail($id, $message, $all, $user);
        $this->Job->saveStatus($jobId, $result);
    }

    public function postsemail()
    {
        if (
            empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2]) ||
            empty($this->args[3]) || empty($this->args[4]) || empty($this->args[5])
        ) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Posts email'] . PHP_EOL);
        }

        $userId = intval($this->args[0]);
        $postId = intval($this->args[1]);
        $eventId = intval($this->args[2]);
        $title = $this->args[3];
        $message = $this->args[4];
        $this->Job->id = intval($this->args[5]);

        $result = $this->Post->sendPostsEmail($userId, $postId, $eventId, $title, $message);

        if ($result) {
            $this->Job->save([
                'progress' => 100,
                'message' => 'Emails sent.',
                'date_modified' => date('Y-m-d H:i:s'),
                'status' =>  Job::STATUS_COMPLETED
            ]);
        } else {
            $this->Job->save([
                'date_modified' => date('Y-m-d H:i:s'),
                'status' =>  Job::STATUS_FAILED
            ]);
        }
    }

    public function enqueueCaching()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Enqueue caching'] . PHP_EOL);
        }

        $timestamp = $this->args[0];
        $task = $this->Task->findByType('cache_exports');

        // If the next execution time and the timestamp don't match, it means that this task is no longer valid as the time for the execution has since being scheduled
        // been updated.
        if ($task['Task']['next_execution_time'] != $timestamp) return;

        $users = $this->User->find('all', array(
                'recursive' => -1,
                'conditions' => array(
                        'Role.perm_site_admin' => 0,
                        'User.disabled' => 0,
                ),
                'contain' => array(
                        'Organisation' => array('fields' => array('name')),
                        'Role' => array('fields' => array('perm_site_admin'))
                ),
                'fields' => array('User.org_id', 'User.id'),
                'group' => array('User.org_id')
        ));
        $site_admin = $this->User->find('first', array(
                'recursive' => -1,
                'conditions' => array(
                        'Role.perm_site_admin' => 1,
                        'User.disabled' => 0
                ),
                'contain' => array(
                        'Organisation' => array('fields' => array('name')),
                        'Role' => array('fields' => array('perm_site_admin'))
                ),
                'fields' => array('User.org_id', 'User.id')
        ));
        $users[] = $site_admin;

        if ($task['Task']['timer'] > 0)    $this->Task->reQueue($task, 'cache', 'EventShell', 'enqueueCaching', false, false);

        // Queue a set of exports for admins. This "ADMIN" organisation. The organisation of the admin users doesn't actually matter, it is only used to indentify
        // the special cache files containing all events
        $i = 0;
        foreach ($users as $user) {
            foreach ($this->Event->exportTypes() as $k => $type) {
                if ($k == 'stix') continue;
                $this->Job->cache($k, $user['User']);
                $i++;
            }
        }
        $this->Task->id = $task['Task']['id'];
        $this->Task->saveField('message', $i . ' job(s) started at ' . date('d/m/Y - H:i:s') . '.');
    }

    public function publish()
    {
        if (empty($this->args[0]) || empty($this->args[2]) || empty($this->args[3])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Publish event'] . PHP_EOL);
        }

        $id = $this->args[0];
        $passAlong = $this->args[1];
        $jobId = $this->args[2];
        $userId = $this->args[3];
        $user = $this->getUser($userId);
        $job = $this->Job->find('first', [
            'recursive' => -1,
            'conditions' => [
                'Job.id' => $jobId
            ]
        ]);
        if (empty($job)) {
            $log = ClassRegistry::init('Log');
            $log->createLogEntry($user, 'publish', 'Event', $id, 'Event (' . $id . '): could not be published - valid job not found.', '');
            return true;
        }
        $this->Event->Behaviors->unload('SysLogLogable.SysLogLogable');
        $result = $this->Event->publish($id, $passAlong);
        $job['Job']['progress'] = 100;
        $job['Job']['status'] = Job::STATUS_COMPLETED;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        if ($result) {
            $job['Job']['message'] = 'Event published.';
        } else {
            $job['Job']['message'] = 'Event published, but the upload to other instances may have failed.';
        }
        $this->Job->save($job);
        $log = ClassRegistry::init('Log');
        $log->createLogEntry($user, 'publish', 'Event', $id, 'Event (' . $id . '): published.', 'published () => (1)');
    }

    public function publish_sightings()
    {
        if (empty($this->args[0]) || empty($this->args[2]) || empty($this->args[3])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Publish sightings'] . PHP_EOL);
        }

        list($id, $passAlong, $jobId, $userId) = $this->args;
        $user = $this->getUser($userId);

        $sightingsUuidsToPush = [];
        if (isset($this->args[4])) { // push just specific sightings
            $sightingsUuidsToPush = $this->getBackgroundJobsTool()->fetchDataFile($this->args[4]);
        }

        $this->Event->Behaviors->unload('SysLogLogable.SysLogLogable');
        $result = $this->Event->publishSightings($id, $passAlong, $sightingsUuidsToPush);

        $count = count($sightingsUuidsToPush);
        $message = $count === 0 ? "All sightings published" : "$count sightings published";
        if ($result) {
            $message .= '.';
        } else {
            $message .= ', but the upload to other instances may have failed.';
        }
        $this->Job->saveStatus($jobId, true, $message);

        $log = ClassRegistry::init('Log');
        $title = $count === 0 ? "All sightings for event published."  : "$count sightings for event published.";
        $log->createLogEntry($user, 'publish_sightings', 'Event', $id, $title, 'publish_sightings updated');
    }

    public function publish_galaxy_clusters()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2]) || !array_key_exists(3, $this->args)) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Publish Galaxy clusters'] . PHP_EOL);
        }

        $clusterId = $this->args[0];
        $jobId = $this->args[1];
        $userId = $this->args[2];
        $passAlong = $this->args[3];
        $user = $this->getUser($userId);
        $job = $this->Job->read(null, $jobId);
        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $result = $this->GalaxyCluster->publish($clusterId, $passAlong=$passAlong);
        $job['Job']['progress'] = 100;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        if ($result) {
            $job['Job']['message'] = 'Galaxy cluster published.';
        } else {
            $job['Job']['message'] = 'Galaxy cluster published, but the upload to other instances may have failed.';
        }
        $this->Job->save($job);
        $log = ClassRegistry::init('Log');
        $log->createLogEntry($user, 'publish', 'GalaxyCluster', $clusterId, 'GalaxyCluster (' . $clusterId . '): published.', 'published () => (1)');
    }

    public function attribute_enrichment()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Run attribute enrichment'] . PHP_EOL);
        }

        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $id = $this->args[1];
        $modulesRaw = $this->args[2];
        try {
            $modules = json_decode($modulesRaw, true);
        } catch (Exception $e) {
            die('Invalid module JSON');
        }
        if (!empty($this->args[3])) {
            $jobId = $this->args[3];
        } else {
            $this->Job->create();
            $data = [
                    'worker' => 'default',
                    'job_type' => 'enrichment',
                    'job_input' => 'Attribute: ' . $id . ' modules: ' . $modulesRaw,
                    'status' => 0,
                    'retries' => 0,
                    'org' => $user['Organisation']['name'],
                    'message' => 'Enriching event.',
            ];
            $this->Job->save($data);
            $jobId = $this->Job->id;
        }
        $job = $this->Job->read(null, $jobId);
        $options = array(
            'user' => $user,
            'id' => $id,
            'modules' => $modules
        );
        $result = $this->Attribute->enrichment($options);
        $job['Job']['progress'] = 100;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        if ($result) {
            $job['Job']['message'] = 'Added ' . $result . ' attribute' . ($result > 1 ? 's.' : '.');
        } else {
            $job['Job']['message'] = 'Enrichment finished, but no attributes added.';
        }
        echo $job['Job']['message'] . PHP_EOL;
        $this->Job->save($job);
        $log = ClassRegistry::init('Log');
        $log->createLogEntry($user, 'enrichment', 'Attribute', $id, 'Attribute (' . $id . '): enriched.', 'enriched () => (1)');
    }

    public function enrichment()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Run enrichment'] . PHP_EOL);
        }

        $userId = $this->args[0];
        $user = $this->getUser($userId);
        $eventId = $this->args[1];
        $modulesRaw = $this->args[2];
        try {
            $modules = json_decode($modulesRaw, true);
        } catch (Exception $e) {
            die('Invalid module JSON');
        }
        if (!empty($this->args[3])) {
            $jobId = $this->args[3];
        } else {
            $this->Job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'enrichment',
                    'job_input' => 'Event: ' . $eventId . ' modules: ' . $modulesRaw,
                    'status' => 0,
                    'retries' => 0,
                    'org' => $user['Organisation']['name'],
                    'message' => 'Enriching event.',
            );
            $this->Job->save($data);
            $jobId = $this->Job->id;
        }
        $job = $this->Job->read(null, $jobId);
        $options = array(
            'user' => $user,
            'event_id' => $eventId,
            'modules' => $modules
        );
        $result = $this->Event->enrichment($options);
        $job['Job']['progress'] = 100;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        if ($result) {
            $job['Job']['message'] = 'Added ' . $result . ' attribute' . ($result > 1 ? 's.' : '.');
        } else {
            $job['Job']['message'] = 'Enrichment finished, but no attributes added.';
        }
        echo $job['Job']['message'] . PHP_EOL;
        $this->Job->save($job);
        $log = ClassRegistry::init('Log');
        $log->createLogEntry($user, 'enrichment', 'Event', $eventId, 'Event (' . $eventId . '): enriched.', 'enriched () => (1)');
    }

    public function processfreetext()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Process free text'] . PHP_EOL);
        }

        $inputFile = $this->args[0];
        $inputData = $this->getBackgroundJobsTool()->fetchDataFile($inputFile);
        Configure::write('CurrentUserId', $inputData['user']['id']);
        $this->Event->processFreeTextData(
            $inputData['user'],
            $inputData['attributes'],
            $inputData['id'],
            $inputData['default_comment'],
            $inputData['proposals'],
            $inputData['adhereToWarninglists'],
            $inputData['jobId']
        );
        return true;
    }

    public function processmoduleresult()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Process module result'] . PHP_EOL);
        }

        $inputFile = $this->args[0];
        $inputData = $this->getBackgroundJobsTool()->fetchDataFile($inputFile);
        Configure::write('CurrentUserId', $inputData['user']['id']);
        $this->Event->processModuleResultsData(
            $inputData['user'],
            $inputData['misp_format'],
            $inputData['id'],
            $inputData['default_comment'],
            $inputData['jobId']
        );
        return true;
    }

    public function recoverEvent()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['event_management_tasks']['data']['Recover event'] . PHP_EOL);
        }

        $jobId = $this->args[0];
        $id = $this->args[1];
        $job = $this->Job->read(null, $jobId);
        $job['Job']['progress'] = 1;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        $job['Job']['message'] = __('Recovering event %s', $id);
        $this->Job->save($job);
        $result = $this->Event->recoverEvent($id);
        $job['Job']['progress'] = 100;
        $job['Job']['date_modified'] = date("Y-m-d H:i:s");
        $job['Job']['message'] = __('Recovery complete. Event #%s recovered, using %s log entries.', $id, $result);
        $this->Job->save($job);
    }

    public function testEventNotificationEmail()
    {
        list($eventId, $userId) = $this->args;
        $send = $this->param('send');

        $user = $this->getUser($userId);
        $eventForUser = $this->Event->fetchEvent($user, [
            'eventid' => $eventId,
            'includeAllTags' => true,
            'includeEventCorrelations' => true,
            'noEventReports' => true,
            'noSightings' => true,
            'metadata' => Configure::read('MISP.event_alert_metadata_only') || Configure::read('MISP.publish_alerts_summary_only'),
        ]);
        if (empty($eventForUser)) {
            $this->error("Event with ID $eventId not exists or given user don't have permission to access it.");
        }

        $emailTemplate = $this->Event->prepareAlertEmail($eventForUser[0], $user);

        App::uses('SendEmail', 'Tools');
        App::uses('GpgTool', 'Tools');
        $sendEmail = new SendEmail(GpgTool::initializeGpg());
        if (!$send) {
            $sendEmail->setTransport('Debug');
        }
        $result = $sendEmail->sendToUser(['User' => $user], null, $emailTemplate);

        if ($send) {
            var_dump($result);
        } else {
            echo $result['contents']['headers'] . "\n\n" . $result['contents']['message'] . "\n";
        }
    }

    public function reportValidationIssuesAttributes()
    {
        foreach ($this->Event->Attribute->reportValidationIssuesAttributes() as $validationIssue) {
            echo $this->json($validationIssue) . "\n";
        }
    }

    public function normalizeIpAddress()
    {
        $dryRun = $this->param('dry-run');

        $count = 0;
        foreach ($this->Event->Attribute->normalizeIpAddress($dryRun) as $attribute) {
            $count++;
            echo JsonTool::encode($attribute) . "\n";
        }

        if ($dryRun) {
            $this->err(__n("%s attribute to fix", "%s attributes to fix", $count, $count));
        } else {
            $this->err(__n("%s attribute fixed", "%s attributes fixed", $count, $count));
        }
    }

    public function generateTopCorrelations()
    {
        $jobId = $this->args[0] ?? null;
        if ($jobId) {
            $job = $this->Job->read(null, $jobId);
            $job['Job']['progress'] = 1;
            $job['Job']['date_modified'] = date("Y-m-d H:i:s");
            $job['Job']['message'] = __('Generating top correlations list.');
            $this->Job->save($job);
        }
        $this->Correlation->generateTopCorrelations($jobId);
        if ($jobId) {
            $job['Job']['progress'] = 100;
            $job['Job']['date_modified'] = date("Y-m-d H:i:s");
            $job['Job']['message'] = __('Job done.');
            $this->Job->save($job);
        }
    }

    /**
     * @param int $userId
     * @return array
     */
    private function getUser($userId)
    {
        $user = $this->User->getAuthUser($userId, true);
        if (empty($user)) {
            $this->error("User with ID $userId does not exist.");
        }
        Configure::write('CurrentUserId', $user['id']); // for audit logging purposes
        return $user;
    }
}
