<?php
App::uses('AppModel', 'Model');
App::uses('ClamAvTool', 'Tools');

class AttachmentScan extends AppModel
{
    const TYPE_ATTRIBUTE = 'Attribute',
        TYPE_SHADOW_ATTRIBUTE = 'ShadowAttribute';

    /** @var AttachmentTool */
    private $attachmentTool;

    /** @var mixed|null  */
    private $clamAvConfig;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->clamAvConfig = Configure::read('MISP.clam_av');
    }

    /**
     * @return bool
     */
    public function isEnabled()
    {
        return !empty($this->clamAvConfig);
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
            'order_by' => 'timestamp DESC', // newest first
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
     * @param array $attribute
     * @return bool|null Return true if attachment is infected.
     * @throws Exception
     */
    public function scanAttachment($type, array $attribute)
    {
        $this->checkType($type);

        if (!isset($attribute['type'])) {
            throw new InvalidArgumentException("Invalid attribute provided.");
        }

        if ($attribute['type'] !== 'attachment') {
            throw new InvalidArgumentException("Just attachment attributes can be scanned, attribute with type '{$attribute['type']}' provided.");
        }

        if (!$this->isEnabled()) {
            throw new Exception("ClamAV is not configured.");
        }

        if ($this->attachmentTool()->attachmentDirIsS3()) {
            throw new Exception("S3 attachment storage is not supported now for AV scanning.");
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

        if (!$file->open()) {
            throw new Exception("Could not open file '$file->path' for reading.");
        }

        $clamAv = new ClamAvTool($this->clamAvConfig);
        $output = $clamAv->scanResource($file->handle);

        if ($output['found']) {
            $this->insertScan($type, $attribute['id'], true, $output['name']);
            return true;

        } else {
            $this->insertScan($type, $attribute['id'], false);
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
            // Try to connect to ClamAV before we will scan all files
            $clamAv = new ClamAvTool($this->clamAvConfig);
            $clamAvVersion = $clamAv->version();
            $clamAvVersion = "{$clamAvVersion['version']}/{$clamAvVersion['databaseVersion']}";
        } catch (Exception $e) {
            $job->saveStatus($jobId, false, 'Could not get ClamAV version');
            $this->logException('Could not get ClamAV version', $e);
            return false;
        }

        $scanned = 0;
        $fails = 0;
        $virusFound = 0;
        foreach ($attributes as $attribute) {
            $type = isset($attribute['Attribute']) ? self::TYPE_ATTRIBUTE : self::TYPE_SHADOW_ATTRIBUTE;
            try {
                $infected = $this->scanAttachment($type, $attribute[$type]);
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

            $message = "$scanned files scanned, $virusFound malware files found (by ClamAV $clamAvVersion).";
            $job->saveProgress($jobId, $message, ($scanned + $fails) / count($attributes) * 100);
        }

        if ($scanned === 0 && $fails > 0) {
            $job->saveStatus($jobId, false);
            return false;
        } else {
            $message = "$scanned files scanned, $virusFound malware files found (by ClamAV $clamAvVersion).";
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
