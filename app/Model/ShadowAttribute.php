<?php
App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');
App::uses('AttachmentTool', 'Tools');
App::uses('ComplexTypeTool', 'Tools');
App::uses('ServerSyncTool', 'Tools');
App::uses('AttributeValidationTool', 'Tools');

/**
 * @property Event $Event
 * @property Attribute $Attribute
 * @property-read array $typeDefinitions
 * @property-read array $categoryDefinitions
 */
class ShadowAttribute extends AppModel
{
    public $combinedKeys = array('event_id', 'category', 'type');

    public $name = 'ShadowAttribute';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'),
        'Trim',
        'Containable',
        'Regexp' => array('fields' => array('value', 'value2')),
    );

    public $belongsTo = array(
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'event_id',
            'conditions' => '',
            'fields' => '',
            'order' => '',
            'counterCache' => true
        ),
        'Org' => array(
                'className' => 'Organisation',
                'foreignKey' => 'org_id'
        ),
        'EventOrg' => array(
                'className' => 'Organisation',
                'foreignKey' => 'event_org_id'
        ),
        'Attribute' => array(
            'className' => 'Attribute',
            'foreignKey' => 'old_id'
        )
    );

    public $displayField = 'value';

    public $virtualFields = array(
            'value' => "CASE WHEN ShadowAttribute.value2 = '' THEN ShadowAttribute.value1 ELSE CONCAT(ShadowAttribute.value1, '|', ShadowAttribute.value2) END",
    ); // TODO hardcoded

    // explanations of certain fields to be used in various views
    public $fieldDescriptions = array(
            'signature' => array('desc' => 'Is this attribute eligible to automatically create an IDS signature (network IDS or host IDS) out of it ?'),
    );

    public $order = array("ShadowAttribute.event_id" => "DESC", "ShadowAttribute.type" => "ASC");

    public $validate = array(
        'event_id' => array(
            'numeric' => array(
                'rule' => array('numeric')
            )
        ),
        'org_id' => array(
            'numeric' => array(
                'rule' => array('numeric')
            )
        ),
        'event_org_id' => array(
            'numeric' => array(
                'rule' => array('numeric')
            )
        ),
        'type' => array(
            // currently when adding a new attribute type we need to change it in both places
            'rule' => array('validateTypeValue'),
            'message' => 'Options depend on the selected category.',
            //'allowEmpty' => false,
            'required' => true,
            //'last' => false, // Stop validation after this rule
            //'on' => 'create', // Limit validation to 'create' or 'update' operations

        ),
        // this could be initialized from categoryDefinitions but dunno how at the moment
        'category' => array(
            'validCategory' => array(
                'rule' => array('validCategory'),
                'message' => 'Options : Payload delivery, Antivirus detection, Payload installation, Files dropped ...'
            ),
        ),
        'value' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty'),
            ),
            'userdefined' => array(
                'rule' => array('validateAttributeValue'),
                'message' => 'Value not in the right type/format. Please double check the value or select type "other".',
            ),
        ),
        'to_ids' => array(
            'boolean' => array(
                'rule' => 'boolean',
                'required' => false,
            ),
        ),
        'uuid' => array(
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ),
        ),
        'proposal_to_delete' => array(
            'boolean' => array(
                'rule' => 'boolean',
            ),
        ),
        'first_seen' => array(
            'rule' => array('datetimeOrNull'),
            'required' => false,
            'message' => array('Invalid ISO 8601 format'),
        ),
        'last_seen' => array(
            'datetimeOrNull' => array(
                'rule' => array('datetimeOrNull'),
                'required' => false,
                'message' => array('Invalid ISO 8601 format'),
            ),
            'validateLastSeenValue' => array(
                'rule' => array('validateLastSeenValue'),
                'required' => false,
                'message' => array('Last seen value should be greater than first seen value')
            ),
        )
    );

    public function __isset($name)
    {
        if ($name === 'typeDefinitions' || $name === 'categoryDefinitions') {
            return true;
        }
        return parent::__isset($name);
    }

    public function __get($name)
    {
        if ($name === 'categoryDefinitions') {
            return $this->Attribute->categoryDefinitions;
        } else if ($name === 'typeDefinitions') {
            return $this->Attribute->typeDefinitions;
        }
        return parent::__get($name);
    }

    // The Associations below have been created with all possible keys, those that are not needed can be removed

    public function beforeSave($options = array())
    {
        // explode value of composite type in value1 and value2
        // or copy value to value1 if not composite type
        if (!empty($this->data['ShadowAttribute']['type'])) {
            $compositeTypes = $this->getCompositeTypes();
            // explode composite types in value1 and value2
            $pieces = explode('|', $this->data['ShadowAttribute']['value']);
            if (in_array($this->data['ShadowAttribute']['type'], $compositeTypes, true)) {
                if (2 != count($pieces)) {
                    throw new InternalErrorException('Composite type, but value not explodable');
                }
                $this->data['ShadowAttribute']['value1'] = $pieces[0];
                $this->data['ShadowAttribute']['value2'] = $pieces[1];
            } else {
                $total = implode('|', $pieces);
                $this->data['ShadowAttribute']['value1'] = $total;
                $this->data['ShadowAttribute']['value2'] = '';
            }
        }
        if (!isset($this->data['ShadowAttribute']['deleted'])) {
            $this->data['ShadowAttribute']['deleted'] = 0;
        }
        if ($this->data['ShadowAttribute']['deleted']) {
            // correlations for proposals are deprecated.
            //$this->__beforeDeleteCorrelation($this->data['ShadowAttribute']);
        }

        // convert into utc and micro sec
        $this->data = $this->Attribute->ISODatetimeToUTC($this->data, $this->alias);

        $trigger_id = 'shadow-attribute-before-save';
        $isTriggerCallable = $this->isTriggerCallable($trigger_id);
        if ($isTriggerCallable) {
            $triggerData = $this->data;
            $shadowAttribute_id = $triggerData['ShadowAttribute']['id'] ?? 0;
            $workflowErrors = [];
            $logging = [
                'model' => 'ShadowAttribute',
                'action' => 'add',
                'id' => $shadowAttribute_id,
                'message' => __('The workflow `%s` prevented the saving of this proposal.', $trigger_id)
            ];
            $workflowSuccess = $this->executeTrigger($trigger_id, $triggerData, $workflowErrors, $logging);
            if (!$workflowSuccess) {
                return false;
            }
        }
        return true;
    }

    private function __beforeDeleteCorrelation($sa)
    {
        if (isset($sa['ShadowAttribute'])) {
            $sa = $sa['ShadowAttribute'];
        }
        $this->ShadowAttributeCorrelation = ClassRegistry::init('ShadowAttributeCorrelation');
        $this->ShadowAttributeCorrelation->deleteAll(array('ShadowAttributeCorrelation.1_shadow_attribute_id' => $sa['id']));
    }

    private function __afterSaveCorrelation($sa)
    {
        if (isset($sa['ShadowAttribute'])) {
            $sa = $sa['ShadowAttribute'];
        }
        if (in_array($sa['type'], Attribute::NON_CORRELATING_TYPES, true)) {
            return;
        }
        $this->ShadowAttributeCorrelation = ClassRegistry::init('ShadowAttributeCorrelation');
        $shadow_attribute_correlations = array();
        $correlatingValues = array($sa['value1']);
        if (!empty($sa['value2'])) {
            $correlatingValues[] = $sa['value2'];
        }
        foreach ($correlatingValues as $k => $cV) {
            $correlatingAttributes[$k] = $this->Attribute->find('all', array(
                    'conditions' => array(
                            'AND' => array(
                                    'OR' => array(
                                            'Attribute.value1' => $cV,
                                            'Attribute.value2' => $cV
                                    ),
                                    'Attribute.type !=' => Attribute::NON_CORRELATING_TYPES,
                                    'Attribute.deleted' => 0,
                                    'Attribute.event_id !=' => $sa['event_id']
                            ),
                    ),
                    'recursive => -1',
                    'fields' => array('Attribute.event_id', 'Attribute.id', 'Attribute.distribution', 'Attribute.sharing_group_id'),
                    'contain' => array('Event' => array('fields' => array('Event.id', 'Event.date', 'Event.info', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id'))),
                    'order' => array(),
            ));
            foreach ($correlatingAttributes as $key => $cA) {
                foreach ($cA as $corr) {
                    $shadow_attribute_correlations[] = array(
                            'value' => $correlatingValues[$key],
                            '1_event_id' => $sa['event_id'],
                            '1_shadow_attribute_id' => $sa['id'],
                            'event_id' => $corr['Attribute']['event_id'],
                            'attribute_id' => $corr['Attribute']['id'],
                            'org_id' => $corr['Event']['org_id'],
                            'distribution' => $corr['Event']['distribution'],
                            'a_distribution' => $corr['Attribute']['distribution'],
                            'sharing_group_id' => $corr['Event']['sharing_group_id'],
                            'a_sharing_group_id' => $corr['Attribute']['sharing_group_id'],
                            'date' => $corr['Event']['date'],
                            'info' => $corr['Event']['info'],
                    );
                }
            }
        }
        if (!empty($shadow_attribute_correlations)) {
            $this->ShadowAttributeCorrelation->saveMany($shadow_attribute_correlations);
        }
    }

    public function afterSave($created, $options = array())
    {
        $result = true;
        // if the 'data' field is set on the $this->data then save the data to the correct file
        if (isset($this->data['ShadowAttribute']['deleted']) && $this->data['ShadowAttribute']['deleted']) {
            $sa = $this->find('first', array('conditions' => array('ShadowAttribute.id' => $this->data['ShadowAttribute']['id']), 'recursive' => -1, 'fields' => array('ShadowAttribute.id', 'ShadowAttribute.event_id', 'ShadowAttribute.type')));
            if ($this->typeIsAttachment($sa['ShadowAttribute']['type'])) {
                $this->loadAttachmentTool()->deleteShadow($sa['ShadowAttribute']['event_id'], $sa['ShadowAttribute']['id']);
            }
        } else {
            if (isset($this->data['ShadowAttribute']['type']) && $this->typeIsAttachment($this->data['ShadowAttribute']['type']) && !empty($this->data['ShadowAttribute']['data'])) {
                $result = $result && $this->saveBase64EncodedAttachment($this->data['ShadowAttribute']);
            }
        }
        /*
         * correlations are deprecated for proposals
        if ((isset($this->data['ShadowAttribute']['deleted']) && $this->data['ShadowAttribute']['deleted']) || (isset($this->data['ShadowAttribute']['proposal_to_delete']) && $this->data['ShadowAttribute']['proposal_to_delete'])) {
            // this is a deletion
            // Could be a proposal to delete or flagging a proposal that it was discarded / accepted - either way, we don't want to correlate here for now
        } else {
            $this->__afterSaveCorrelation($this->data['ShadowAttribute']);
        }
        */
        if (empty($this->data['ShadowAttribute']['deleted'])) {
            $action = $created ? 'add' : 'edit';
            $this->publishKafkaNotification('shadow_attribute', $this->data, $action);
        }
        return $result;
    }

    public function beforeDelete($cascade = true)
    {
        // delete attachments from the disk
        $this->read(); // first read the attribute from the db
        if ($this->typeIsAttachment($this->data['ShadowAttribute']['type'])) {
            $this->loadAttachmentTool()->deleteShadow($this->data['ShadowAttribute']['event_id'], $this->data['ShadowAttribute']['id']);
        }
    }

    public function beforeValidate($options = array())
    {
        $proposal = &$this->data['ShadowAttribute'];
        if (!isset($proposal['type'])) {
            $this->invalidate('type', 'No value provided.');
            return false;
        }

        if (!isset($proposal['comment'])) {
            $proposal['comment'] = '';
        }

        // make some changes to the inserted value
        if (isset($proposal['value'])) {
            $value = trim($proposal['value']);
            $value = ComplexTypeTool::refangValue($value, $proposal['type']);
            $value = AttributeValidationTool::modifyBeforeValidation($proposal['type'], $value);
            $proposal['value'] = $value;
        }

        if (!isset($proposal['org'])) {
            $proposal['org'] = '';
        }

        if (empty($proposal['timestamp'])) {
            $proposal['timestamp'] = time();
        }

        if (!isset($proposal['proposal_to_delete'])) {
            $proposal['proposal_to_delete'] = 0;
        }

        // generate UUID if it doesn't exist
        if (empty($proposal['uuid'])) {
            $proposal['uuid'] = CakeText::uuid();
        } else {
            $proposal['uuid'] = strtolower($proposal['uuid']);
        }

        if (empty($proposal['category'])) {
            $proposal['category'] = $this->Attribute->typeDefinitions[$proposal['type']]['default_category'];
        }

        if (isset($proposal['first_seen'])) {
            $proposal['first_seen'] = $proposal['first_seen'] === '' ? null : $proposal['first_seen'];
        }
        if (isset($proposal['last_seen'])) {
            $proposal['last_seen'] = $proposal['last_seen'] === '' ? null : $proposal['last_seen'];
        }

        return true;
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as &$v) {
            $proposal = &$v['ShadowAttribute'];
            if (!empty($proposal['first_seen'])) {
                $proposal['first_seen'] = $this->microTimestampToIso($proposal['first_seen']);
            }
            if (!empty($proposal['last_seen'])) {
                $proposal['last_seen'] = $this->microTimestampToIso($proposal['last_seen']);
            }
        }
        return $results;
    }

    public function validateTypeValue($fields)
    {
        $category = $this->data['ShadowAttribute']['category'];
        if (isset($this->categoryDefinitions[$category]['types'])) {
            return in_array($fields['type'], $this->categoryDefinitions[$category]['types'], true);
        }
        return false;
    }

    public function validCategory($fields)
    {
        return $this->Attribute->validCategory($fields);
    }

    public function validateAttributeValue($fields)
    {
        $value = $fields['value'];
        return AttributeValidationTool::validate($this->data['ShadowAttribute']['type'], $value);
    }

    public function getCompositeTypes()
    {
        return $this->Attribute->getCompositeTypes();
    }

    public function typeIsMalware($type)
    {
        return $this->Attribute->typeIsMalware($type);
    }

    public function typeIsAttachment($type)
    {
        return $this->Attribute->typeIsAttachment($type);
    }

    public function base64EncodeAttachment(array $attribute)
    {
        try {
            return base64_encode($this->getAttachment($attribute));
        } catch (NotFoundException $e) {
            $this->log($e->getMessage(), LOG_NOTICE);
            return '';
        }
    }

    public function getAttachment($attribute, $path_suffix='')
    {
        return $this->loadAttachmentTool()->getShadowContent($attribute['event_id'], $attribute['id'], $path_suffix);
    }

    public function saveBase64EncodedAttachment($attribute)
    {
        $data = base64_decode($attribute['data']);
        $result = $this->loadAttachmentTool()->saveShadow($attribute['event_id'], $attribute['id'], $data);
        if ($result) {
            $this->loadAttachmentScan()->backgroundScan(AttachmentScan::TYPE_SHADOW_ATTRIBUTE, $attribute);
        }
        return $result;
    }

    /**
     * @param array $shadowAttribute
     * @param string $path_suffix
     * @return File
     * @throws Exception
     */
    public function getAttachmentFile(array $shadowAttribute, $path_suffix='')
    {
        return $this->loadAttachmentTool()->getShadowFile($shadowAttribute['event_id'], $shadowAttribute['id'], $path_suffix);
    }

    public function checkComposites()
    {
        $compositeTypes = $this->getCompositeTypes();
        $fails = array();
        $attributes = $this->find('all', array('recursive' => 0));

        foreach ($attributes as $attribute) {
            if ((in_array($attribute['ShadowAttribute']['type'], $compositeTypes)) && (!strlen($attribute['ShadowAttribute']['value1']) || !strlen($attribute['ShadowAttribute']['value2']))) {
                $fails[] = $attribute['ShadowAttribute']['event_id'] . ':' . $attribute['ShadowAttribute']['id'];
            }
        }
        return $fails;
    }

    // check whether the variable is null or datetime
    public function datetimeOrNull($fields)
    {
        return $this->Attribute->datetimeOrNull($fields);
    }

    public function validateLastSeenValue($fields)
    {
        $ls = $fields['last_seen'];
        if (!isset($this->data['ShadowAttribute']['first_seen']) || is_null($ls)) {
            return true;
        }
        $converted = $this->Attribute->ISODatetimeToUTC(['ShadowAttribute' => [
            'first_seen' => $this->data['ShadowAttribute']['first_seen'],
            'last_seen' => $ls
        ]], 'ShadowAttribute');
        if ($converted['ShadowAttribute']['first_seen'] > $converted['ShadowAttribute']['last_seen']) {
            return false;
        }
        return true;
    }

    public function setDeleted($id)
    {
        $this->Behaviors->detach('SysLogLogable.SysLogLogable');
        $sa = $this->find('first', array('conditions' => array('ShadowAttribute.id' => $id), 'recusive' => -1));
        if (empty($sa)) {
            return false;
        }
        $date = new DateTime();
        $sa['ShadowAttribute']['deleted'] = 1;
        $sa['ShadowAttribute']['timestamp'] = $date->getTimestamp();
        $this->save($sa);
        return true;
    }

    public function findOldProposal($sa)
    {
        $oldsa = $this->find('first', array(
            'conditions' => array(
                'ShadowAttribute.event_uuid' => $sa['event_uuid'],
                'ShadowAttribute.uuid' => $sa['uuid'],
                'ShadowAttribute.value' => $sa['value'],
                'ShadowAttribute.type' => $sa['type'],
                'ShadowAttribute.category' => $sa['category'],
                'ShadowAttribute.to_ids' => $sa['to_ids'],
                'ShadowAttribute.comment' => $sa['comment']
            ),
        ));
        if (empty($oldsa)) {
            return false;
        } else {
            return $oldsa['ShadowAttribute'];
        }
    }

    /**
     * @param int $eventId
     * @return array Key is organisation ID, value is an organisation name
     */
    public function getEventContributors($eventId)
    {
        $orgIds = $this->find('column', array(
            'fields' => array('ShadowAttribute.org_id'),
            'conditions' => array('event_id' => $eventId),
            'unique' => true,
            'order' => false
        ));
        if (empty($orgIds)) {
            return [];
        }

        $this->Organisation = ClassRegistry::init('Organisation');
        return $this->Organisation->find('list', array(
            'recursive' => -1,
            'fields' => array('id', 'name'),
            'conditions' => array('Organisation.id' => $orgIds)
        ));
    }

    /**
     * Sends an email to members of the organization that owns the event
     * @param int $id  The event id
     * @return boolean False if no email at all was sent, true if at least an email was sent
     */
    public function sendProposalAlertEmail($id)
    {
        $this->Event->recursive = -1;
        $event = $this->Event->read(null, $id);

        // If the event has an e-mail lock, return
        if ($event['Event']['proposal_email_lock'] == 1) {
            return false;
        } else {
            $this->setProposalLock($id);
        }
        $this->User = ClassRegistry::init('User');
        $this->User->recursive = -1;
        $orgMembers = $this->User->find('all', array(
                'conditions' => array(
                        'org_id' => $event['Event']['orgc_id'],
                        'contactalert' => 1,
                        'disabled' => 0
                ),
                'fields' => array('email', 'gpgkey', 'certif_public', 'contactalert', 'id', 'disabled'),
        ));

        $body = "Hello, \n\n";
        $body .= "A user of another organisation has proposed a change to an event created by you or your organisation. \n\n";
        $body .= 'To view the event in question, follow this link: ' . Configure::read('MISP.baseurl') . '/events/view/' . $id . "\n";
        $subject =  "[" . Configure::read('MISP.org') . " MISP] Proposal to event #" . $id . ' (uuid: ' . $event['Event']['uuid'] . ')';
        $result = false;
        foreach ($orgMembers as $user) {
            $result = $this->User->sendEmail($user, $body, $body, $subject) or $result;
        }
        return $result;
    }


    public function setProposalLock($id, $lock = true)
    {
        $this->Event->recursive = -1;
        $event = $this->Event->read(null, $id);
        if ($lock) {
            $event['Event']['proposal_email_lock'] = 1;
        } else {
            $event['Event']['proposal_email_lock'] = 0;
        }
        $fieldList = array('proposal_email_lock', 'id', 'info');
        $event['Event']['skip_zmq'] = 1;
        $event['Event']['skip_kafka'] = 1;
        $this->Event->save($event, array('fieldList' => $fieldList));
    }

    public function generateCorrelation($jobId = false)
    {
        $this->ShadowAttributeCorrelation = ClassRegistry::init('ShadowAttributeCorrelation');
        $this->ShadowAttributeCorrelation->deleteAll(array('id !=' => 0), false);
        // get all proposals..
        $proposals = $this->find('all', array('recursive' => -1, 'conditions' => array('ShadowAttribute.deleted' => 0, 'ShadowAttribute.proposal_to_delete' => 0)));
        $proposalCount = count($proposals);
        if ($jobId && Configure::read('MISP.background_jobs')) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;
        }
        if ($proposalCount > 0) {
            foreach ($proposals as $k => $proposal) {
                $this->__afterSaveCorrelation($proposal['ShadowAttribute']);
                if ($jobId && Configure::read('MISP.background_jobs') && $k > 0 && $proposalCount % $k == 10) {
                    $this->Job->saveField('progress', ($k / $proposalCount * 100));
                }
            }
        }
        if ($jobId && Configure::read('MISP.background_jobs')) {
            $this->Job->saveField('progress', 100);
            $this->Job->saveField('status', 4);
            $this->Job->saveField('message', 'Job done.');
        }
        return $proposalCount;
    }

    /**
     * @param array $proposal
     * @return array|false
     */
    private function __preCaptureMassage(array $proposal)
    {
        if (empty($proposal['event_uuid']) || empty($proposal['Org'])) {
            return false;
        }
        if (isset($proposal['id'])) {
            unset($proposal['id']);
        }
        $event = $this->Event->find('first', array(
            'recursive' => -1,
            'conditions' => array('Event.uuid' => $proposal['event_uuid']),
            'fields' => array('Event.id', 'Event.uuid', 'Event.org_id')
        ));
        if (empty($event)) {
            return false;
        }
        $proposal['event_id'] = $event['Event']['id'];
        $proposal['event_org_id'] = $event['Event']['org_id'];
        return $proposal;
    }

    public function capture($proposal, $user)
    {
        $proposal = $this->__preCaptureMassage($proposal);
        if ($proposal === false) {
            return false;
        }
        $oldsa = $this->findOldProposal($proposal);
        if (!$oldsa || $oldsa['timestamp'] < $proposal['timestamp']) {
            if ($oldsa) {
                $this->delete($oldsa['id']);
            }
            if (isset($proposal['old_id'])) {
                $oldAttribute = $this->Attribute->find('first', array('recursive' => -1, 'conditions' => array('Attribute.uuid' => $proposal['uuid'])));
                if ($oldAttribute) {
                    $proposal['old_id'] = $oldAttribute['Attribute']['id'];
                } else {
                    $proposal['old_id'] = 0;
                }
            } else {
                $proposal['old_id'] = 0;
            }
            $proposal['org_id'] = $this->Event->Orgc->captureOrg($proposal['Org'], $user);
            unset($proposal['Org']);
            $this->create();
            if ($this->save($proposal)) {
                if (!isset($proposal['deleted']) || !$proposal['deleted']) {
                    $this->sendProposalAlertEmail($proposal['event_id']);
                }
                return true;
            }
        }
        return false;
    }

    /**
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return int
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public function pullProposals(array $user, ServerSyncTool $serverSync)
    {
        if (!$serverSync->isSupported(ServerSyncTool::FEATURE_PROPOSALS)) {
            return 0;
        }

        $serverSync->debug("Pulling proposals");

        $i = 1;
        $fetchedCount = 0;
        $chunkSize = 1000;
        $timestamp = strtotime("-90 day");
        while (true) {
            try {
                $data = $serverSync->fetchProposals([
                    'all' => 1,
                    'timestamp' => $timestamp,
                    'limit' => $chunkSize,
                    'page' => $i,
                    'deleted' => [0, 1],
                ])->json();
            } catch (Exception $e) {
                $this->logException("Could not fetch page $i of proposals from remote server {$serverSync->server()['Server']['id']}", $e);
                return $fetchedCount;
            }
            $returnSize = count($data);
            if ($returnSize === 0) {
                return $fetchedCount;
            }
            foreach ($data as $proposal) {
                $result = $this->capture($proposal['ShadowAttribute'], $user);
                if ($result) {
                    $fetchedCount++;
                }
            }
            if ($returnSize < $chunkSize) {
                return $fetchedCount;
            }
            $i++;
        }
    }

    public function buildConditions($user)
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->Event->SharingGroup->authorizedIds($user);
            $attributeDistribution = array(
                'Attribute.distribution' => array(1,2,3,5)
            );
            $objectDistribution = array(
                '(SELECT distribution FROM objects WHERE objects.id = Attribute.object_id)' => array(1,2,3,5)
            );
            if (!empty($sgids) && (!isset($sgids[0]) || $sgids[0] != -1)) {
                $objectDistribution['(SELECT sharing_group_id FROM objects WHERE objects.id = Attribute.object_id)'] = $sgids;
                $attributeDistribution['Attribute.sharing_group_id'] = $sgids;
            }
            $unpublishedPrivate = Configure::read('MISP.unpublishedprivate');
            $conditions = array(
                'AND' => array(
                    'OR' => array(
                        'Event.org_id' => $user['org_id'],
                        ['AND' => [
                            'Event.distribution' => array(1,2,3),
                            $unpublishedPrivate ? ['Event.published' => 1] : [],
                        ]],
                        ['AND' => [
                            'Event.distribution' => 4,
                            'Event.sharing_group_id' => $sgids,
                            $unpublishedPrivate ? ['Event.published' => 1] : [],
                        ]],
                    ),
                    array(
                        'OR' => array(
                            'ShadowAttribute.old_id' => '0',
                            'AND' => array(
                                array(
                                    'OR' => array(
                                        'Attribute.object_id' => '0',
                                        array(
                                            'OR' => $objectDistribution
                                        )
                                    )
                                ),
                                array(
                                    'OR' => $attributeDistribution
                                )
                            )
                        )
                    )
                )
            );
        }
        return $conditions;
    }

    public function upgradeToProposalCorrelation()
    {
        $this->Log = ClassRegistry::init('Log');
        if (!Configure::read('MISP.background_jobs')) {
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                    'org' => 'SYSTEM',
                    'model' => 'Server',
                    'model_id' => 0,
                    'email' => 'SYSTEM',
                    'action' => 'update_database',
                    'user_id' => 0,
                    'title' => 'Starting proposal correlation generation',
                    'change' => 'The generation of Proposal correlations as part of the 2.4.20 datamodel upgrade has started'
            ));
            $count = $this->generateCorrelation();
            $this->Log->create();
            if (is_numeric($count)) {
                $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_database',
                        'user_id' => 0,
                        'title' => 'Proposal correlation generation complete',
                        'change' => 'The generation of Proposal correlations as part of the 2.4.20 datamodel upgrade is completed. ' . $count . ' proposals used.'
                ));
            } else {
                $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_database',
                        'user_id' => 0,
                        'title' => 'Proposal correlation generation failed',
                        'change' => 'The generation of Proposal correlations as part of the 2.4.20 has failed. You can rerun it from the administrative tools.'
                ));
            }
        } else {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'generate proposal correlation',
                'All attributes',
                'Correlating Proposals.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'jobGenerateShadowAttributeCorrelation',
                    $jobId
                ],
                true,
                $jobId
            );

            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                    'org' => 'SYSTEM',
                    'model' => 'Server',
                    'model_id' => 0,
                    'email' => 'SYSTEM',
                    'action' => 'update_database',
                    'user_id' => 0,
                    'title' => 'Proposal correlation generation job queued',
                    'change' => 'The job for the generation of Proposal correlations as part of the 2.4.20 datamodel upgrade has been queued'
            ));
        }
    }

    public function saveAttachment($shadowAttribute, $path_suffix='')
    {
        $result = $this->loadAttachmentTool()->saveShadow($shadowAttribute['event_id'], $shadowAttribute['id'], $shadowAttribute['data'], $path_suffix);
        if ($result) {
            $this->loadAttachmentScan()->backgroundScan(AttachmentScan::TYPE_SHADOW_ATTRIBUTE, $shadowAttribute);
        }
        return $result;
    }

    /**
     * @param array $shadowAttribute
     * @param bool $thumbnail
     * @param int $maxWidth - When $thumbnail is true
     * @param int $maxHeight - When $thumbnail is true
     * @return string
     * @throws Exception
     */
    public function getPictureData(array $shadowAttribute, $thumbnail=false, $maxWidth=200, $maxHeight=200)
    {
        if ($thumbnail && extension_loaded('gd')) {
            if ($maxWidth == 200 && $maxHeight == 200) {
                // Return thumbnail directly if already exists
                try {
                    return $this->getAttachment($shadowAttribute['ShadowAttribute'], $path_suffix = '_thumbnail');
                } catch (NotFoundException $e) {
                    // pass
                }
            }

            // Thumbnail doesn't exists, we need to generate it
            $imageData = $this->getAttachment($shadowAttribute['ShadowAttribute']);
            $imageData = $this->loadAttachmentTool()->resizeImage($imageData, $maxWidth, $maxHeight);

            // Save just when requested default thumbnail size
            if ($maxWidth == 200 && $maxHeight == 200) {
                $shadowAttribute['ShadowAttribute']['data'] = $imageData;
                $this->saveAttachment($shadowAttribute['ShadowAttribute'], $path_suffix='_thumbnail');
            }
        } else {
            $imageData = $this->getAttachment($shadowAttribute['ShadowAttribute']);
        }

        return $imageData;
    }
}
