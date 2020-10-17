<?php
App::uses('AppModel', 'Model');
App::uses('ClamAvTool', 'Tools');

class AttachmentScan extends AppModel
{
    const TYPE_ATTRIBUTE = 'Attribute',
        TYPE_SHADOW_ATTRIBUTE = 'ShadowAttribute';

    /** @var AttachmentTool */
    private $attachmentTool;

    /** @var Module */
    private $moduleModel;

    /** @var mixed|null  */
    private $attachmentScanModuleName;

    private $signatureTemplates = [
        '4dbb56ef-4763-4c97-8696-a2bfc305cf8e', // av-signature
        '984c5c39-be7f-4e1e-b034-d3213bac51cb', // sb-signature
    ];

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->attachmentScanModuleName = Configure::read('MISP.attachment_scan_module');
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
     * @param null $jobId
     * @return bool|string
     */
    public function scan($type, $attributeId = null, $jobId = null)
    {
        /** @var Job $job */
        $job = ClassRegistry::init('Job');
        if ($jobId && !$job->exists($jobId)) {
            $jobId = null;
        }

        if (!$this->isEnabled()) {
            throw new Exception("Malware scanning module is not configured.");
        }

        if ($this->attachmentTool()->attachmentDirIsS3()) {
            throw new Exception("S3 attachment storage is not supported now for AV scanning.");
        }

        if ($type === 'all') {
            $attributes = ClassRegistry::init('Attribute')->find('all', array(
                'recursive' => -1,
                'conditions' => ['type' => 'attachment'],
                'fields' => ['id', 'type', 'event_id'],
            ));
            $shadowAttributes = ClassRegistry::init('ShadowAttribute')->find('all', array(
                'recursive' => -1,
                'conditions' => ['type' => 'attachment'],
                'fields' => ['id', 'type', 'event_id'],
            ));
            $attributes = array_merge($attributes, $shadowAttributes);
        } else if ($type === self::TYPE_ATTRIBUTE) {
            $attributes = ClassRegistry::init('Attribute')->find('all', array(
                'recursive' => -1,
                'conditions' => ['type' => 'attachment', 'id' => $attributeId],
                'fields' => ['id', 'type', 'event_id'],
            ));
        } else if ($type === self::TYPE_SHADOW_ATTRIBUTE) {
            $attributes = ClassRegistry::init('ShadowAttribute')->find('all', array(
                'recursive' => -1,
                'conditions' => ['type' => 'attachment', 'id' => $attributeId],
                'fields' => ['id', 'type', 'event_id'],
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
            $moduleOptions = $this->loadModuleOptions($this->attachmentScanModuleName);
        } catch (Exception $e) {
            $job->saveStatus($jobId, false, 'Could not connect to malware protection module.');
            $this->logException('Could not connect to malware protection module.', $e);
            return false;
        }

        $scanned = 0;
        $fails = 0;
        $virusFound = 0;
        foreach ($attributes as $attribute) {
            $type = isset($attribute['Attribute']) ? self::TYPE_ATTRIBUTE : self::TYPE_SHADOW_ATTRIBUTE;
            try {
                $infected = $this->scanAttachment($type, $attribute[$type], $moduleOptions);
                if ($infected === true) {
                    $virusFound++;
                }
                $scanned++;
            } catch (NotFoundException $e) {
                // skip
            } catch (Exception $e) {
                $this->logException("Could not scan attachment for $type {$attribute['Attribute']['id']}", $e);
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
            $job->create();
            $job->save(array(
                'worker' => 'default',
                'job_type' => 'virus_scan',
                'job_input' => ($type === self::TYPE_ATTRIBUTE ? 'Attribute: ' : 'Shadow attribute: ') . $attribute['id'],
                'status' => 0,
                'retries' => 0,
                'org' => 'SYSTEM',
                'message' => 'Scanning...',
            ));
            $jobId = $job->id;

            $processId = CakeResque::enqueue(
                'default',
                'AdminShell',
                array('scanAttachment', $type, $attribute['id'], $jobId),
                true
            );
            $job->saveField('process_id', $processId);
        }
    }

    /**
     * @param string $type
     * @param array $attribute
     * @param array $moduleOptions
     * @return bool|null Return true if attachment is infected.
     * @throws Exception
     */
    private function scanAttachment($type, array $attribute, array $moduleOptions)
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

        /* if ($file->size() > 50 * 1024 * 1024) {
             $this->log("File '$file->path' is bigger than 50 MB, will be not scanned.", LOG_NOTICE);
             return false;
         }*/

        $fileContent = $file->read();
        if ($fileContent === false) {
            throw new Exception("Could not open file '$file->path' for reading.");
        }
        $attribute['data'] = base64_encode($fileContent);

        $results = $this->sendToModule($attribute, $moduleOptions);

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
     * @param array $moduleOptions
     * @return array
     * @throws Exception
     */
    private function sendToModule(array $attribute, array $moduleOptions)
    {
        $data = json_encode([
            'module' => $this->attachmentScanModuleName,
            'attribute' => $attribute,
            'event_id' => $attribute['event_id'],
            'config' => $moduleOptions,
        ]);

        $exception = null;
        $results = $this->moduleModel()->queryModuleServer('/query', $data, false, 'Enrichment', $exception);
        if (!is_array($results)) {
            throw new Exception($results, 0, $exception);
        }
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
            if (in_array($object['template_uuid'], $this->signatureTemplates)) {
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
    private function loadModuleOptions($moduleName)
    {
        $exception = null;
        $modules = $this->moduleModel()->getModules(false, 'Enrichment', $exception);
        if (!is_array($modules)) {
            throw new Exception($modules, 0, $exception);
        }

        $module = null;
        foreach ($modules['modules'] as $temp) {
            if ($temp['name'] === $moduleName) {
                $module = $temp;
                break;
            }
        }

        if (!$module) {
            throw new Exception("Module $moduleName doesn't exists.");
        }

        if (!in_array('expansion', $module['meta']['module-type'])) {
            throw new Exception("Module $moduleName must be expansion type.");
        }

        if (!in_array('attachment', $module['mispattributes']['input'])) {
            throw new Exception("Module $moduleName doesn't support 'attachment' input type.");
        }

        if (!isset($module['mispattributes']['format']) || $module['mispattributes']['format'] !== 'misp_standard') {
            throw new Exception("Module $moduleName doesn't support misp_standard output format.");
        }

        $options = [];
        if (isset($module['meta']['config'])) {
            foreach ($module['meta']['config'] as $conf) {
                $options[$conf] = Configure::read("Plugin.Enrichment_{$moduleName}_$conf");
            }
        }
        return $options;
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
        if (!in_array($type, [self::TYPE_ATTRIBUTE, self::TYPE_SHADOW_ATTRIBUTE])) {
            throw new InvalidArgumentException("Type must be 'Attribute' or 'ShadowAttribute', '$type' provided.");
        }
    }
}
