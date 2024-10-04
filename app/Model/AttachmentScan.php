<?php
App::uses('AppModel', 'Model');

class AttachmentScan extends AppModel
{
    const TYPE_ATTRIBUTE = 'Attribute',
        TYPE_SHADOW_ATTRIBUTE = 'ShadowAttribute';

    // base64 encoded eicar.exe
    const EICAR = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=';

    /** @var AttachmentTool */
    private $attachmentTool;

    /** @var Module */
    private $moduleModel;

    /** @var mixed|null  */
    private $attachmentScanModuleName;

    /**
     * List of supported object templates
     * @var string[]
     */
    const SIGNATURE_TEMPLATES = [
        '4dbb56ef-4763-4c97-8696-a2bfc305cf8e', // av-signature
        '984c5c39-be7f-4e1e-b034-d3213bac51cb', // sb-signature
    ];

    /**
     * List of supported ways how to send data to module. From the most reliable to worst.
     * @var string[]
     */
    private $possibleTypes = [
        'attachment',
        'sha3-512',
        'sha3-384',
        'sha3-256',
        'sha3-224',
        'sha512',
        'sha512/224',
        'sha512/256',
        'sha384',
        'sha256',
        'sha224',
        'sha1',
        'md5',
    ];

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->attachmentScanModuleName = Configure::read('MISP.attachment_scan_module');

        // This can be useful, if you use third party service (like VirusTotal) and you don't want leak uploaded
        // files payload. Then just file hash will be send.
        if (Configure::read('MISP.attachment_scan_hash_only')) {
            array_shift($this->possibleTypes); // remove 'attachment' type
        }
    }

    /**
     * Checks configuration and connection to module wth AV engine and returns an array of scanning software.
     *
     * @return array
     * @throws Exception
     */
    public function diagnostic()
    {
        if (!$this->isEnabled()) {
            throw new Exception("Malware scanning module is not configured.");
        }

        if ($this->attachmentTool()->attachmentDirIsS3()) {
            throw new Exception("S3 attachment storage is not supported now for malware scanning.");
        }

        $moduleInfo = $this->loadModuleInfo($this->attachmentScanModuleName);

        if (in_array('attachment', $moduleInfo['types'], true)) {
            $fakeAttribute = [
                'uuid' => CakeText::uuid(),
                'event_id' => 1,
                'type' => 'attachment',
                'value' => 'eicar.com',
                'data' => self::EICAR,
            ];
        } else {
            $hashAlgo = $moduleInfo['types'][0];
            $hash = hash($hashAlgo, base64_decode(self::EICAR));
            $fakeAttribute = [
                'uuid' => CakeText::uuid(),
                'event_id' => 1,
                'type' => $hashAlgo,
                'value' => $hash,
            ];
        }
        $results = $this->sendToModule($fakeAttribute, $moduleInfo['config']);
        if (empty($results)) {
            throw new Exception("Eicar test file was not detected.");
        }

        return array_column($results, 'software');
    }

    /**
     * @return bool
     */
    public function isEnabled()
    {
        return !empty($this->attachmentScanModuleName);
    }

    /**
     * @param string $type
     * @param int $attributeId Attribute or Shadow Attribute ID
     * @param bool $infected
     * @param string|null $malwareName
     * @return bool
     * @throws Exception
     */
    public function insertScan($type, $attributeId, $infected, $malwareName = null)
    {
        $this->checkType($type);
        $this->create();
        $result = $this->save(array(
            'type' => $type,
            'attribute_id' => $attributeId,
            'infected' => $infected,
            'malware_name' => $malwareName,
            'timestamp' => time(),
        ));
        if (!$result) {
            throw new Exception("Could not save scan result for attribute $attributeId: " . json_encode($this->validationErrors));
        }
        return true;
    }

    /**
     * @param string $type
     * @param int $attributeId Attribute or Shadow Attribute ID
     * @return array|null
     */
    public function getLatestScan($type, $attributeId)
    {
        $this->checkType($type);
        return $this->find('first', array(
            'conditions' => array(
                'type' => $type,
                'attribute_id' => $attributeId,
            ),
            'fields' => ['infected', 'malware_name'],
            'order' => 'timestamp DESC', // newest first
        ));
    }

    /**
     * Checks if file is infected according to latest scan. Return values:
     *  - null - file was never checked
     *  - false - file is not infected according to latest scan
     *  - string - file is infected, string contains malware name
     *
     * @param string $type
     * @param int $attributeId Attribute or Shadow Attribute ID
     * @return bool|null|string
     */
    public function isInfected($type, $attributeId)
    {
        $latest = $this->getLatestScan($type, $attributeId);
        if (empty($latest)) {
            return null;
        }
        if ($latest['AttachmentScan']['infected']) {
            return $latest['AttachmentScan']['malware_name'];
        } else {
            return false;
        }
    }

    /**
     * @param string $type
     * @param int $attributeId Attribute or ShadowAttribute ID
     * @param int|null $jobId
     * @return bool|string
     * @throws Exception
     */
    public function scan($type, $attributeId = null, $jobId = null)
    {
        /** @var Job $job */
        $job = ClassRegistry::init('Job');
        if ($jobId && !$job->exists($jobId)) {
            $this->log("Job with ID $jobId not found in database", LOG_NOTICE);
            $jobId = null;
        }

        if (!$this->isEnabled()) {
            throw new Exception("Malware scanning module is not configured.");
        }

        if ($this->attachmentTool()->attachmentDirIsS3()) {
            throw new Exception("S3 attachment storage is not supported now for malware scanning.");
        }

        $fields = ['id', 'uuid', 'type', 'value', 'event_id'];
        if ($type === 'all') {
            $attributes = ClassRegistry::init('MispAttribute')->find('all', array(
                'recursive' => -1,
                'conditions' => ['type' => 'attachment'],
                'fields' => $fields,
            ));
            $shadowAttributes = ClassRegistry::init('ShadowAttribute')->find('all', array(
                'recursive' => -1,
                'conditions' => ['type' => 'attachment'],
                'fields' => $fields,
            ));
            $attributes = array_merge($attributes, $shadowAttributes);
        } else if ($type === self::TYPE_ATTRIBUTE) {
            $attributes = ClassRegistry::init('MispAttribute')->find('all', array(
                'recursive' => -1,
                'conditions' => ['type' => 'attachment', 'id' => $attributeId],
                'fields' => $fields,
            ));
        } else if ($type === self::TYPE_SHADOW_ATTRIBUTE) {
            $attributes = ClassRegistry::init('ShadowAttribute')->find('all', array(
                'recursive' => -1,
                'conditions' => ['type' => 'attachment', 'id' => $attributeId],
                'fields' => $fields,
            ));
        } else {
            throw new InvalidArgumentException("Input must be 'all', 'Attribute' or 'ShadowAttribute', '$type' provided.");
        }

        if (empty($attributes) && $type !== 'all') {
            $message = "$type not found";
            $job->saveStatus($jobId, false, $message);
            return $message;
        }

        try {
            $moduleInfo = $this->loadModuleInfo($this->attachmentScanModuleName);
        } catch (Exception $e) {
            $job->saveStatus($jobId, false, 'Could not connect to attachment scan module.');
            $this->logException('Could not connect to attachment scan module.', $e);
            return false;
        }

        $scanned = 0;
        $fails = 0;
        $virusFound = 0;
        foreach ($attributes as $attribute) {
            $type = isset($attribute['Attribute']) ? self::TYPE_ATTRIBUTE : self::TYPE_SHADOW_ATTRIBUTE;
            try {
                $infected = $this->scanAttachment($type, $attribute[$type], $moduleInfo);
                if ($infected === true) {
                    $virusFound++;
                    $scanned++;
                } else if ($infected === false) {
                    $scanned++;
                }
            } catch (Exception $e) {
                $this->logException("Could not scan attachment for $type {$attribute[$type]['id']}", $e, LOG_WARNING);
                $fails++;
            }

            $message = "$scanned files scanned, $virusFound malware files found.";
            $job->saveProgress($jobId, $message, ($scanned + $fails) / count($attributes) * 100);
        }

        if ($scanned === 0 && $fails > 0) {
            $job->saveStatus($jobId, false);
            return false;
        } else {
            $message = "$scanned files scanned, $virusFound malware files found.";
            if ($fails) {
                $message .= " $fails files failed to scan (see error log for more details).";
            }

            $job->saveStatus($jobId, true, "Job done, $message");
            return $message;
        }
    }

    /**
     * @param string $type
     * @param array $attribute Attribute or Shadow Attribute
     * @throws Exception
     */
    public function backgroundScan($type, array $attribute)
    {
        $this->checkType($type);

        $canScan = $attribute['type'] === 'attachment' &&
            $this->isEnabled() &&
            Configure::read('MISP.background_jobs') &&
            !$this->attachmentTool()->attachmentDirIsS3();

        if ($canScan) {
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_PRIO,
                'virus_scan',
                ($type === self::TYPE_ATTRIBUTE ? 'Attribute: ' : 'Shadow attribute: ') . $attribute['id'],
                'Scanning...'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::PRIO_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'scanAttachment',
                    $type,
                    $attribute['id'],
                    $jobId
                ],
                true,
                $jobId
            );
        }
    }

    /**
     * Return true if attachment is infected, null if attachment was not scanned and false if attachment is OK
     *
     * @param string $type
     * @param array $attribute
     * @param array $moduleInfo
     * @return bool|null
     * @throws Exception
     */
    private function scanAttachment($type, array $attribute, array $moduleInfo)
    {
        if (!isset($attribute['type'])) {
            throw new InvalidArgumentException("Invalid attribute provided.");
        }

        if ($attribute['type'] !== 'attachment') {
            throw new InvalidArgumentException("Just attachment attributes can be scanned, attribute with type '{$attribute['type']}' provided.");
        }

        if ($type === self::TYPE_ATTRIBUTE) {
            $file = $this->attachmentTool()->getFile($attribute['event_id'], $attribute['id']);
        } else {
            $file = $this->attachmentTool()->getShadowFile($attribute['event_id'], $attribute['id']);
        }

        if (in_array('attachment', $moduleInfo['types'], true)) {
            $fileSize = $file->size();
            if ($fileSize === false) {
                throw new Exception("Could not read size of file '$file->path'.");
            }

            if ($fileSize === 0) {
                return false; // empty file is automatically considered as not infected
            }

            if ($fileSize > 25 * 1024 * 1024) {
                $this->log("File '$file->path' is bigger than 25 MB, will be not scanned.", LOG_NOTICE);
                return null;
            }

            $fileContent = $file->read();
            if ($fileContent === false) {
                throw new Exception("Could not read content of file '$file->path'.");
            }
            $attribute['data'] = base64_encode($fileContent);
        } else {
            // Instead of sending whole file to module, just generate file hash and send that hash as fake attribute.
            $hashAlgo = $moduleInfo['types'][0];
            $hash = hash_file($hashAlgo, $file->pwd());
            if (!$hash) {
                throw new Exception("Could not generate $hashAlgo hash for file '$file->path'.");
            }

            $attribute = [
                'uuid' => CakeText::uuid(),
                'event_id' => $attribute['event_id'],
                'type' => $hashAlgo,
                'value' => $hash,
            ];
        }

        $results = $this->sendToModule($attribute, $moduleInfo['config']);

        if (!empty($results)) {
            $signatures = [];
            foreach ($results as $result) {
                $signatures = array_merge($signatures, $result['signatures']);
            }
            $this->insertScan($type, $attribute['id'], true, implode(', ', $signatures));
            return true;

        } else {
            $this->insertScan($type, $attribute['id'], false);
            return false;
        }
    }

    /**
     * @param array $attribute
     * @param array $moduleConfig
     * @return array
     * @throws Exception
     */
    private function sendToModule(array $attribute, array $moduleConfig)
    {
        // How long we will wait for scan result
        $timeout = Configure::read('MISP.attachment_scan_timeout') ?: 30;
        $data = [
            'module' => $this->attachmentScanModuleName,
            'attribute' => $attribute,
            'event_id' => $attribute['event_id'],
            'config' => $moduleConfig,
            'timeout' => $timeout, // module internal timeout
        ];

        $results = $this->moduleModel()->sendRequest('/query', $timeout + 1, $data, 'Enrichment');
        if (isset($results['error'])) {
            throw new Exception("{$this->attachmentScanModuleName} module returns error: " . $results['error']);
        }
        if (!isset($results['results'])) {
            throw new Exception("Invalid data received from {$this->attachmentScanModuleName} module.");
        }
        return $this->extractInfoFromModuleResult($results['results']);
    }

    /**
     * Extracts data from scan results.
     * @param array $results
     * @return array
     * @throws Exception
     */
    private function extractInfoFromModuleResult(array $results)
    {
        if (!isset($results['Object']) || !is_array($results['Object'])) {
            return [];
        }

        $output = [];
        foreach ($results['Object'] as $object) {
            if (!isset($object['template_uuid'])) {
                continue;
            }
            if (in_array($object['template_uuid'], self::SIGNATURE_TEMPLATES, true)) {
                $software = null;
                $signatures = array();
                foreach ($object['Attribute'] as $attribute) {
                    if (!isset($attribute['object_relation']) || !isset($attribute['value'])) {
                        continue;
                    }
                    if ($attribute['object_relation'] === 'signature') {
                        $signatures[] = $attribute['value'];
                    } else if ($attribute['object_relation'] === 'software') {
                        $software = $attribute['value'];
                    }
                }
                if (!empty($signatures) && $software) {
                    $output[] = ['signatures' => $signatures, 'software' => $software];
                }
            }
        }
        return $output;
    }

    /**
     * @param string $moduleName
     * @return array
     * @throws Exception
     */
    private function loadModuleInfo($moduleName)
    {
        $modules = $this->moduleModel()->getModules('Enrichment', true);

        $module = null;
        foreach ($modules as $temp) {
            if (strtolower($temp['name']) === strtolower($moduleName)) {
                $module = $temp;
                break;
            }
        }

        if (!$module) {
            throw new Exception("Module $moduleName not found.");
        }

        if (!in_array('expansion', $module['meta']['module-type'], true)) {
            throw new Exception("Module $moduleName must be expansion type.");
        }

        $types = array_intersect($this->possibleTypes, $module['mispattributes']['input']);
        if (empty($types)) {
            throw new Exception("Module $moduleName doesn't support at least one required type: " . implode(", ", $this->possibleTypes) . ".");
        }

        if (!isset($module['mispattributes']['format']) || $module['mispattributes']['format'] !== 'misp_standard') {
            throw new Exception("Module $moduleName doesn't support misp_standard output format.");
        }

        $config = [];
        if (isset($module['meta']['config'])) {
            foreach ($module['meta']['config'] as $conf) {
                $config[$conf] = Configure::read("Plugin.Enrichment_{$moduleName}_$conf");
            }
        }
        return ['config' => $config, 'types' => $types];
    }

    /**
     * @return AttachmentTool
     */
    private function attachmentTool()
    {
        if (!$this->attachmentTool) {
            $this->attachmentTool = new AttachmentTool();
        }

        return $this->attachmentTool;
    }

    /**
     * @return Module
     */
    private function moduleModel()
    {
        if (!$this->moduleModel) {
            $this->moduleModel = ClassRegistry::init('Module');
        }

        return $this->moduleModel;
    }

    /**
     * @param string $type
     * @raise InvalidArgumentException
     */
    private function checkType($type)
    {
        if (!in_array($type, [self::TYPE_ATTRIBUTE, self::TYPE_SHADOW_ATTRIBUTE], true)) {
            throw new InvalidArgumentException("Type must be 'Attribute' or 'ShadowAttribute', '$type' provided.");
        }
    }
}
