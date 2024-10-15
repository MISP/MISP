<?php
App::uses('AppModel', 'Model');
App::uses('SyncTool', 'Tools');

/**
 * @property Event $Event
 * @property SharingGroup $SharingGroup
 */
class EventReport extends AppModel
{
    public $actsAs = array(
        'AuditLog',
        'Containable',
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ),
        'Regexp' => array('fields' => array('value')),
        'AnalystDataParent',
    );

    public $validate = array(
        'event_id' => array(
            'numeric' => array(
                'rule' => array('numeric')
            )
        ),
        'uuid' => array(
            'uuid' => array(
                'rule' => 'uuid',
                'message' => 'Please provide a valid RFC 4122 UUID'
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'on' => 'create'
            )
        ),
        'name' => [
            'rule' => 'notBlank',
            'required' => true,
        ],
        'distribution' => array(
            'rule' => array('inList', array('0', '1', '2', '3', '4', '5')),
            'message' => 'Options: Your organisation only, This community only, Connected communities, All communities, Sharing group, Inherit event',
            'required' => true
        ),
    );

    const CAPTURE_FIELDS = array('uuid', 'name', 'content', 'distribution', 'sharing_group_id', 'timestamp', 'deleted', 'event_id');
    const DEFAULT_CONTAIN = array(
        'SharingGroup' => array('fields' => array('id', 'name', 'uuid')),
        'Event' => array(
            'fields' =>  array('Event.id', 'Event.orgc_id', 'Event.org_id', 'Event.info', 'Event.user_id', 'Event.date'),
            'Orgc' => array('fields' => array('Orgc.id', 'Orgc.name')),
            'Org' => array('fields' => array('Org.id', 'Org.name'))
        )
    );

    public $belongsTo = array(
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'event_id'
        ),
        'SharingGroup' => array(
            'className' => 'SharingGroup',
            'foreignKey' => 'sharing_group_id'
        ),
    );

    public function beforeValidate($options = array())
    {
        $eventReport = &$this->data['EventReport'];
        if (empty($eventReport['uuid'])) {
            // generate UUID if it doesn't exist
            $eventReport['uuid'] = CakeText::uuid();
        } else {
            $eventReport['uuid'] = strtolower($eventReport['uuid']);
        }
        // generate timestamp if it doesn't exist
        if (empty($eventReport['timestamp'])) {
            $eventReport['timestamp'] = time();
        }
        if ($eventReport['distribution'] != 4) {
            $eventReport['sharing_group_id'] = 0;
        }
        // Set defaults for when some of the mandatory fields don't have defaults
        // These fields all have sane defaults either based on another field, or due to server settings
        if (!isset($eventReport['distribution'])) {
            $eventReport['distribution'] = $this->Event->Attribute->defaultDistribution();
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        $isTriggerCallable = $this->isTriggerCallable('event-report-after-save');
        if ($isTriggerCallable) {
            $report = $this->data['EventReport'];
            $action = $created ? 'add' : 'edit';
            if (!empty($report['deleted'])) {
                $action = 'soft-delete';
            }
            $workflowErrors = [];
            $logging = [
                'model' => 'EventReport',
                'action' => $action,
                'id' => $report['id'],
            ];
            $triggerData = ['EventReport' => $report];
            $this->executeTrigger('event-report-after-save', $triggerData, $workflowErrors, $logging);
        }
    }

    /**
     * captureReport Gets a report then save it
     *
     * @param array $user
     * @param array $report
     * @param int $eventId
     * @return array Any errors preventing the capture
     * @throws Exception
     */
    public function captureReport(array $user, array $report, $eventId)
    {
        if (!isset($report['EventReport'])) {
            $report = ['EventReport' => $report];
        }
        $report['EventReport']['event_id'] = $eventId;
        if (!empty($report['EventReport']['id'])) {
            unset($report['EventReport']['id']);
        }
        $report = $this->captureSG($user, $report);
        $this->create();
        $errors = $this->saveAndReturnErrors($report, ['fieldList' => self::CAPTURE_FIELDS]);
        if (!empty($errors)) {
            $this->loadLog()->createLogEntry($user, 'add', 'EventReport', 0,
                __('Event Report dropped due to validation for Event report %s failed: %s', $this->data['EventReport']['uuid'], $this->data['EventReport']['name']),
                __('Validation errors: %s.%sFull report: %s', json_encode($errors), PHP_EOL, json_encode($report['EventReport']))
            );
        } else {
            $savedReport = $this->find('first', [
                'recursive' => -1,
                'fields' => ['id', 'uuid'],
                'conditions' => ['id' => $this->id],
            ]);
            if ($savedReport) {
                $this->Event->captureAnalystData($user, $report, 'EventReport', $savedReport['EventReport']['uuid']);
            }
        }
        return $errors;
    }

    /**
     * addReport Add a report
     *
     * @param  array $user
     * @param  array $report
     * @param  int|string $eventId
     * @return array Any errors preventing the addition
     */
    public function addReport(array $user, array $report, $eventId)
    {
        $errors = $this->captureReport($user, $report, $eventId);
        if (empty($errors)) {
            $this->Event->unpublishEvent($eventId);
        }
        return $errors;
    }

    /**
     * editReport Edit a report
     *
     * @param  array $user
     * @param  array $report
     * @param  int|string $eventId
     * @param  bool  $fromPull
     * @param  bool  $nothingToChange
     * @return array Any errors preventing the edition
     */
    public function editReport(array $user, array $report, $eventId, $fromPull = false, &$nothingToChange = false)
    {
        $errors = array();
        if (!isset($report['EventReport']['uuid'])) {
            if ($fromPull) {
                $report['EventReport']['uuid'] = $attribute['uuid'] = CakeText::uuid();
            } else {
                $errors[] = __('Event Report doesn\'t have an UUID');
                return $errors;
            }
        }
        $report['EventReport']['event_id'] = $eventId;
        $existingReport = $this->find('first', array(
            'conditions' => array('EventReport.uuid' => $report['EventReport']['uuid']),
            'recursive' => -1,
        ));
        if (empty($existingReport)) {
            if ($fromPull) {
                return $this->captureReport($user, $report, $eventId);
            } else {
                $errors[] = __('Event Report not found.');
                return $errors;
            }
        } else {
            $report['EventReport']['id'] = $existingReport['EventReport']['id'];
        }

        if ($fromPull) {
            if (isset($report['EventReport']['timestamp'])) {
                if ($report['EventReport']['timestamp'] <= $existingReport['EventReport']['timestamp']) {
                    $nothingToChange = true;
                    return array();
                }
            }
        } else {
            unset($report['EventReport']['timestamp']);
        }
        $errors = $this->saveAndReturnErrors($report, ['fieldList' => self::CAPTURE_FIELDS], $errors);
        if (empty($errors)) {
            $this->Event->captureAnalystData($user, $report['EventReport'], 'EventReport', $report['EventReport']['uuid']);
            if (!$fromPull) {
                $this->Event->unpublishEvent($eventId);
            }
        }
        return $errors;
    }

    /**
     * deleteReport ACL-aware method to delete the report.
     *
     * @param  array $user
     * @param  int|string $id
     * @param  bool $hard
     * @return array Any errors preventing the deletion
     */
    public function deleteReport(array $user, $report, $hard=false)
    {
        $report = $this->fetchIfAuthorized($user, $report, 'delete', $throwErrors=true, $full=false);
        $errors = [];
        if ($hard) {
            $deleted = $this->delete($report['EventReport']['id'], true);
            if (!$deleted) {
                $errors[] = __('Failed to delete report');
            }
        } else {
            $report['EventReport']['deleted'] = true;
            $errors = $this->saveAndReturnErrors($report, ['fieldList' => ['deleted']]);
        }
        if (empty($errors)) {
            $this->Event->unpublishEvent($report['EventReport']['event_id']);
        }
        return $errors;
    }

    /**
     * restoreReport ACL-aware method to restore a report.
     *
     * @param  array $user
     * @param  int|string $id
     * @return array Any errors preventing the restoration
     */
    public function restoreReport(array $user, $id)
    {
        $report = $this->fetchIfAuthorized($user, $id, 'edit', $throwErrors=true, $full=false);
        $report['EventReport']['deleted'] = false;
        $errors = $this->saveAndReturnErrors($report, ['fieldList' => ['deleted']]);
        if (empty($errors)) {
            $this->Event->unpublishEvent($report['EventReport']['event_id']);
        }
        return $errors;
    }

    private function captureSG(array $user, array $report)
    {
        $this->Event = ClassRegistry::init('Event');
        if (isset($report['EventReport']['distribution']) && $report['EventReport']['distribution'] == 4) {
            $report['EventReport'] = $this->Event->captureSGForElement($report['EventReport'], $user);
        }
        return $report;
    }

    /**
     * buildACLConditions Generate ACL conditions for viewing the report
     *
     * @param  array $user
     * @return array
     */
    public function buildACLConditions(array $user)
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->SharingGroup->authorizedIds($user);
            $eventConditions = $this->Event->createEventConditions($user);
            $conditions = array(
                'AND' => array(
                    $eventConditions['AND'],
                    array(
                        'OR' => array(
                            'Event.org_id' => $user['org_id'],
                            'EventReport.distribution' => array('1', '2', '3', '5'),
                            'AND '=> array(
                                'EventReport.distribution' => 4,
                                'EventReport.sharing_group_id' => $sgids,
                            )
                        )
                    )
                )
            );
        }
        return $conditions;
    }

    /**
     * buildACLConditions Generate ACL conditions for viewing the report
     *
     * @param  array $user
     * @param  array $events
     * @return array
     */
    public function attachReportCountsToEvents(array $user, $events)
    {
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->SharingGroup->authorizedIds($user);
        }
        foreach ($events as $k => $event) {
            $conditions = [
                'AND' => [
                    [
                        'Event.id' => $event['Event']['id']
                    ]
                ]
            ];
            if (!$user['Role']['perm_site_admin'] && $event['Event']['org_id'] != $user['org_id']) {
                $conditions['AND'][] = [
                    'EventReport.distribution' => [1, 2, 3, 5],
                    'AND '=> [
                        'EventReport.distribution' => 4,
                        'EventReport.sharing_group_id' => $sgids,
                    ]
                ];
            }
            $events[$k]['Event']['report_count'] = $this->find('count', [
                'conditions' => $conditions
            ]);
        }
        return $events;
    }


    /**
     * fetchById Simple ACL-aware method to fetch a report by Id or UUID
     *
     * @param  array $user
     * @param  int|string $reportId
     * @param  bool  $throwErrors
     * @param  bool  $full
     * @return array
     */
    public function simpleFetchById(array $user, $reportId, $throwErrors=true, $full=false)
    {
        if (is_numeric($reportId)) {
            $options = array('conditions' => array("EventReport.id" => $reportId));
        } elseif (Validation::uuid($reportId)) {
            $options = array('conditions' => array("EventReport.uuid" => $reportId));
        } else {
            if ($throwErrors) {
                throw new NotFoundException(__('Invalid report'));
            }
            return array();
        }

        $report = $this->fetchReports($user, $options, $full);
        if (!empty($report)) {
            return $report[0];
        }
        if ($throwErrors) {
            throw new NotFoundException(__('Invalid report'));
        }
        return array();
    }

    /**
     * fetchReports ACL-aware method. Basically find with ACL
     *
     * @param  array $user
     * @param  array $options
     * @param  bool  $full
     * @return array
     */
    public function fetchReports(array $user, array $options = array(), $full=false)
    {
        $params = array(
            'conditions' => $this->buildACLConditions($user),
            'contain' => self::DEFAULT_CONTAIN,
            'recursive' => -1
        );
        if ($full) {
            $params['recursive'] = 1;
        }
        if (isset($options['fields'])) {
            $params['fields'] = $options['fields'];
        }
        if (isset($options['conditions'])) {
            $params['conditions']['AND'][] = $options['conditions'];
        }
        if (isset($options['group'])) {
            $params['group'] = empty($options['group']) ? $options['group'] : false;
        }
        $reports = $this->find('all', $params);
        return $reports;
    }

    /**
     * fetchIfAuthorized Fetches a report and checks if the user has the authorization to perform the requested operation
     *
     * @param  array $user
     * @param  int|string|array $report
     * @param  mixed $authorizations the requested actions to be performed on the report
     * @param  bool  $throwErrors Should the function throws excpetion if users is not allowed to perform the action
     * @param  bool  $full
     * @return array The report or an error message
     */
    public function fetchIfAuthorized(array $user, $report, $authorizations, $throwErrors=true, $full=false)
    {
        $authorizations = is_array($authorizations) ? $authorizations : array($authorizations);
        $possibleAuthorizations = array('view', 'edit', 'delete');
        if (!empty(array_diff($authorizations, $possibleAuthorizations))) {
            throw new NotFoundException(__('Invalid authorization requested'));
        }
        if (isset($report['uuid'])) {
            $report['EventReport'] = $report;
        }
        if (!isset($report['EventReport']['uuid'])) {
            $report = $this->simpleFetchById($user, $report, $throwErrors=$throwErrors, $full=$full);
            if (empty($report)) {
                $message = __('Invalid report');
                return array('authorized' => false, 'error' => $message);
            }
        }
        if ($user['Role']['perm_site_admin']) {
            return $report;
        }

        if (in_array('view', $authorizations) && count($authorizations) == 1) {
            return $report;
        } else {
            if (in_array('edit', $authorizations) || in_array('delete', $authorizations)) {
                $checkResult = $user['Role']['perm_site_admin'] || ($report['Event']['orgc_id'] === $user['org_id']);
                if ($checkResult !== true) {
                    if ($throwErrors) {
                        throw new UnauthorizedException($checkResult);
                    }
                    return array('authorized' => false, 'error' => $checkResult);
                }
            }
            return $report;
        }
    }

    public function reArrangeReport(array $report)
    {
        $rearrangeObjects = array('Event', 'SharingGroup');
        if (isset($report['EventReport'])) {
            foreach ($rearrangeObjects as $ro) {
                if (isset($report[$ro]) && !is_null($report[$ro]['id'])) {
                    $report['EventReport'][$ro] = $report[$ro];
                }
                unset($report[$ro]);
            }
        }
        return $report;
    }

    /**
     * getProxyMISPElements Extract MISP Elements from an event and make them accessible by their UUID
     *
     * @param array $user
     * @param int|string $eventid
     * @return array
     * @throws Exception
     */
    public function getProxyMISPElements(array $user, $eventid)
    {
        $options = [
            'noSightings' => true,
            'sgReferenceOnly' => true,
            'noEventReports' => true,
            'noShadowAttributes' => true,
        ];

        $event = $this->Event->fetchEvent($user, array_merge(['eventid' => $eventid], $options));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event'));
        }
        $event = $event[0];

        if (!empty($event['Event']['extends_uuid'])) {
            $extendedParentEvent = $this->Event->fetchEvent($user, array_merge([
                'event_uuid' => $event['Event']['extends_uuid'],
                'extended' => true,
            ], $options));
            if (!empty($extendedParentEvent)) {
                $event = $extendedParentEvent[0];
            }
        }

        $allTagNames = [];
        foreach ($event['EventTag'] as $eventTag) {
            // include just tags that belongs to requested event or its parent, not to other child
            if ($eventTag['event_id'] == $eventid || $eventTag['event_id'] == $event['Event']['id']) {
                $allTagNames[$eventTag['Tag']['name']] = $eventTag['Tag'];
            }
        }

        $attributes = [];
        foreach ($event['Attribute'] as $attribute) {
            unset($attribute['ShadowAttribute']);
            foreach ($attribute['AttributeTag'] as $at) {
                $allTagNames[$at['Tag']['name']] = $at['Tag'];
            }
            $this->Event->Attribute->removeGalaxyClusterTags($attribute);
            $attributes[$attribute['uuid']] = $attribute;
        }

        $objects = [];
        $templateConditions = [];
        foreach ($event['Object'] as $k => $object) {
            if (isset($object['Attribute'])) {
                foreach ($object['Attribute'] as &$objectAttribute) {
                    unset($objectAttribute['ShadowAttribute']);
                    $objectAttribute['object_uuid'] = $object['uuid'];
                    $attributes[$objectAttribute['uuid']] = $objectAttribute;

                    foreach ($objectAttribute['AttributeTag'] as $at) {
                        $allTagNames[$at['Tag']['name']] = $at['Tag'];
                    }
                    $this->Event->Attribute->removeGalaxyClusterTags($objectAttribute);
                }
            }
            $objects[$object['uuid']] = $object;

            $uniqueCondition = "{$object['template_uuid']}.{$object['template_version']}";
            if (!isset($templateConditions[$uniqueCondition])) {
                $templateConditions[$uniqueCondition]['AND'] = [
                    'ObjectTemplate.uuid' => $object['template_uuid'],
                    'ObjectTemplate.version' => $object['template_version']
                ];
            }
        }
        if (!empty($templateConditions)) {
            // Fetch object templates for event objects
            $this->ObjectTemplate = ClassRegistry::init('ObjectTemplate');
            $templates = $this->ObjectTemplate->find('all', array(
                'conditions' => ['OR' => array_values($templateConditions)],
                'recursive' => -1,
                'contain' => array(
                    'ObjectTemplateElement' => [
                        'order' => ['ui-priority' => 'DESC'],
                        'fields' => ['object_relation', 'type', 'ui-priority']
                    ]
                )
            ));
            $objectTemplates = [];
            foreach ($templates as $template) {
                $objectTemplates["{$template['ObjectTemplate']['uuid']}.{$template['ObjectTemplate']['version']}"] = $template;
            }
        } else {
            $objectTemplates = [];
        }
        $this->Galaxy = ClassRegistry::init('Galaxy');
        $allowedGalaxies = $this->Galaxy->getAllowedMatrixGalaxies();
        $allowedGalaxies = Hash::combine($allowedGalaxies, '{n}.Galaxy.uuid', '{n}.Galaxy');
        return [
            'attribute' => $attributes,
            'object' => $objects,
            'objectTemplates' => $objectTemplates,
            'galaxymatrix' => $allowedGalaxies,
            'tagname' => $allTagNames
        ];
    }

    private function saveAndReturnErrors($data, $saveOptions = [], $errors = [])
    {
        $saveSuccess = $this->save($data, $saveOptions);
        if (!$saveSuccess) {
            foreach ($this->validationErrors as $validationError) {
                $errors[] = $validationError[0];
            }
        }
        return $errors;
    }

    public function applySuggestions(array $user, array $report, $contentWithSuggestions, array $suggestionsMapping)
    {
        $errors = [];
        $replacedContent = $contentWithSuggestions;
        $success = 0;
        foreach ($suggestionsMapping as $value => $suggestedAttribute) {
            $suggestedAttribute['value'] = $value;
            $savedAttribute = $this->createAttributeFromSuggestion($user, $report, $suggestedAttribute);
            if (empty($savedAttribute['errors'])) {
                $success++;
                $replacedContent = $this->applySuggestionsInText($replacedContent, $savedAttribute['attribute'], $value);
            } else {
                $replacedContent = $this->revertToOriginalInText($replacedContent, $value);
                $errors[] = $savedAttribute['errors'];
            }
        }
        if ($success > 0 || count($suggestionsMapping) == 0) {
            $report['EventReport']['content'] = $replacedContent;
            $editErrors = $this->editReport($user, $report, $report['EventReport']['event_id']);
            if (!empty($editErrors)) {
                $errors[] = $editErrors;
            }
        }
        return $errors;
    }

    public function applySuggestionsInText($contentWithSuggestions, array $attribute, $value)
    {
        $textToBeReplaced = "@[suggestion]($value)";
        $textToInject = "@[attribute]({$attribute['Attribute']['uuid']})";
        $replacedContent = str_replace($textToBeReplaced, $textToInject, $contentWithSuggestions);
        return $replacedContent;
    }

    public function revertToOriginalInText($contentWithSuggestions, $value)
    {
        $textToBeReplaced = sprintf('@[suggestion](%s)', $value);
        $textToInject = $value;
        $replacedContent = str_replace($textToBeReplaced, $textToInject, $contentWithSuggestions);
        return $replacedContent;
    }

    private function createAttributeFromSuggestion($user, $report, $suggestedAttribute)
    {
        $errors = [];
        $attribute = [
            'event_id' => $report['EventReport']['event_id'],
            'distribution' => 5,
            'category' => $suggestedAttribute['category'],
            'type' => $suggestedAttribute['type'],
            'value' => $suggestedAttribute['value'],
            'to_ids' => $suggestedAttribute['to_ids'],
        ];
        $validationErrors = array();
        $this->Event->Attribute->captureAttribute($attribute, $report['EventReport']['event_id'], $user, false, false, false, $validationErrors);
        $savedAttribute = false;
        if (!empty($validationErrors)) {
            $errors = $validationErrors;
        } else {
            $savedAttribute = $this->Event->Attribute->find('first', array(
                'recursive' => -1,
                'conditions' => array('Attribute.id' => $this->Event->Attribute->id),
            ));
        }
        return [
            'errors' => $errors,
            'attribute' => $savedAttribute
        ];
    }

    /**
     * transformFreeTextIntoReplacement
     *
     * @param  array $user
     * @param  array $report
     * @param  array $complexTypeToolResult Uses the complex type tool output to support import regex replacements.
     *                                      Another solution would be to run the regex replacement on each token of the report which is too heavy
     * @return array
     */
    public function transformFreeTextIntoReplacement(array $user, array $report, array $complexTypeToolResult)
    {
        $complexTypeToolResultWithImportRegex = $this->injectImportRegexOnComplexTypeToolResult($complexTypeToolResult);
        $valueToValueWithRegex = Hash::combine($complexTypeToolResultWithImportRegex, '{n}.valueWithImportRegex', '{n}.value');
        $proxyElements = $this->getProxyMISPElements($user, $report['EventReport']['event_id']);
        $originalContent = $report['EventReport']['content'];
        $content = $originalContent;
        $replacedValues = [];
        foreach ($proxyElements['attribute'] as $uuid => $attribute) {
            $count = 0;
            $textToInject = sprintf('@[attribute](%s)', $uuid);
            if (strlen($attribute['value']) < 3) {
                continue;
            }
            $content = str_replace($attribute['value'], $textToInject, $content, $count);
            if ($count > 0 || strpos($originalContent, $attribute['value'])) { // Check if the value has been replaced by the first match
                if (!isset($replacedValues[$attribute['value']])) {
                    $replacedValues[$attribute['value']] = [
                        'attributeUUIDs' => [$uuid],
                        'valueInReport' => $attribute['value'],
                    ];
                } else {
                    $replacedValues[$attribute['value']]['attributeUUIDs'][] = $uuid;
                }
                $count = 0;
            }
            if (isset($valueToValueWithRegex[$attribute['value']]) && $valueToValueWithRegex[$attribute['value']] != $attribute['value']) {
                $content = str_replace($valueToValueWithRegex[$attribute['value']], $textToInject, $content, $count);
                if ($count > 0 || strpos($originalContent, $valueToValueWithRegex[$attribute['value']])) {
                    if (!isset($replacedValues[$attribute['value']])) {
                        $replacedValues[$attribute['value']] = [
                            'attributeUUIDs' => [$uuid],
                            'valueInReport' => $valueToValueWithRegex[$attribute['value']],
                        ];
                    } else {
                        $replacedValues[$attribute['value']]['attributeUUIDs'][] = $uuid;
                    }
                }
            }
        }
        return [
            'contentWithReplacements' => $content,
            'replacedValues' => $replacedValues
        ];
    }

    public function transformFreeTextIntoSuggestion($content, array $complexTypeToolResult)
    {
        $replacedContent = $content;
        $typeToCategoryMapping = $this->Event->Attribute->typeToCategoryMapping();

        // Sort by original value string length, longest values first
        usort($complexTypeToolResult, function ($a, $b) {
           $strlenA = strlen($a['original_value']);
           $strlenB = strlen($b['original_value']);
           if ($strlenA === $strlenB) {
               return 0;
           }
           return ($strlenA < $strlenB) ? 1 : -1;
        });

        $suggestionsMapping = [];
        foreach ($complexTypeToolResult as $complexTypeToolEntry) {
            $textToBeReplaced = $complexTypeToolEntry['value'];
            $textToInject = "@[suggestion]($textToBeReplaced)";
            $suggestionsMapping[$textToBeReplaced] = [
                'category' => $typeToCategoryMapping[$complexTypeToolEntry['default_type']][0],
                'type' => $complexTypeToolEntry['default_type'],
                'value' => $textToBeReplaced,
                'to_ids' => $complexTypeToolEntry['to_ids'] ?? 0,
            ];
            $replacedContent = str_replace($complexTypeToolEntry['original_value'], $textToInject, $replacedContent);
        }
        return [
            'contentWithSuggestions' => $replacedContent,
            'suggestionsMapping' => $suggestionsMapping,
        ];
    }

    public function injectImportRegexOnComplexTypeToolResult($complexTypeToolResult) {
        foreach ($complexTypeToolResult as $i => $complexTypeToolEntry) {
            $transformedValue = $this->runRegexp($complexTypeToolEntry['default_type'], $complexTypeToolEntry['value']);
            if ($transformedValue !== false) {
                $complexTypeToolResult[$i]['valueWithImportRegex'] = $transformedValue;
            }
        }
        return $complexTypeToolResult;
    }

    public function getComplexTypeToolResultWithReplacements(array $user, array $report)
    {
        App::uses('ComplexTypeTool', 'Tools');
        $complexTypeTool = new ComplexTypeTool();
        $this->Warninglist = ClassRegistry::init('Warninglist');
        $complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
        $complexTypeTool->setSecurityVendorDomains($this->Warninglist->fetchSecurityVendorDomains());

        $complexTypeToolResult = $complexTypeTool->checkFreeText($report['EventReport']['content']);
        $replacementResult = $this->transformFreeTextIntoReplacement($user, $report, $complexTypeToolResult);
        $complexTypeToolResult = $complexTypeTool->checkFreeText($replacementResult['contentWithReplacements']);

        return [
            'complexTypeToolResult' => $complexTypeToolResult,
            'replacementResult' => $replacementResult,
        ];
    }

    /**
     * extractWithReplacements Extract context information from report with special care for ATT&CK
     *
     * @param  array $user
     * @param  array $report
     * @param  array $options
     * @return array
     */
    public function extractWithReplacements(array $user, array $report, array $options = [])
    {
        $baseOptions = [
            'replace' => false,
            'tags' => true,
            'synonyms' => true,
            'synonyms_min_characters' => 4,
            'prune_deprecated' => true,
            'attack' => true,
        ];
        $options = array_merge($baseOptions, $options);
        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $mitreAttackGalaxyId = $this->GalaxyCluster->Galaxy->getMitreAttackGalaxyId();
        $clusterContain = ['Tag'];
        $replacedContext = [];

        if ($options['prune_deprecated']) {
            $clusterContain['Galaxy'] = ['conditions' => ['Galaxy.namespace !=' => 'deprecated']];
        }
        if ($options['synonyms']) {
            $clusterContain['GalaxyElement'] = ['conditions' => ['GalaxyElement.key' => 'synonyms']];
        }
        $clusterConditions = [];
        if ($options['attack']) {
            $clusterConditions = ['GalaxyCluster.galaxy_id !=' => $mitreAttackGalaxyId];
        }
        $clusters = $this->GalaxyCluster->find('all', [
            'conditions' => $clusterConditions,
            'contain' => $clusterContain
        ]);

        $originalContent = $report['EventReport']['content'];
        // Remove all existing event report markers
        $content = preg_replace("/@\[(attribute|tag|galaxymatrix)]\([^)]*\)/", '', $originalContent);

        if ($options['tags']) {
            $this->Tag = ClassRegistry::init('Tag');
            $tags = $this->Tag->fetchUsableTags($user);
            foreach ($tags as $tag) {
                $tagName = $tag['Tag']['name'];
                if (strlen($tagName) < 3) {
                    continue;
                }
                $found = $this->isValidReplacementTag($content, $tagName);
                if ($found) {
                    $replacedContext[$tagName][$tagName] = $tag['Tag'];
                } else {
                    $tagNameUpper = strtoupper($tagName);
                    $found = $this->isValidReplacementTag($content, $tagNameUpper);
                    if ($found) {
                        $replacedContext[$tagNameUpper][$tagName] = $tag['Tag'];
                    }
                }
            }
        }

        foreach ($clusters as $cluster) {
            if (strlen($cluster['GalaxyCluster']['value']) > 2) {
                $cluster['GalaxyCluster']['colour'] = '#0088cc';
                $tagName = $cluster['GalaxyCluster']['tag_name'];
                $found = $this->isValidReplacementTag($content, $tagName);
                if ($found) {
                    $replacedContext[$tagName][$tagName] = $cluster['GalaxyCluster'];
                }
                $toSearch = ' ' . $cluster['GalaxyCluster']['value'] . ' ';
                $found = strpos($originalContent, $toSearch) !== false;
                if ($found) {
                    $replacedContext[$cluster['GalaxyCluster']['value']][$tagName] = $cluster['GalaxyCluster'];
                }
                if ($options['synonyms']) {
                    foreach ($cluster['GalaxyElement'] as $element) {
                        if (strlen($element['value']) >= $options['synonyms_min_characters']) {
                            $toSearch = ' ' . $element['value'] . ' ';
                            $found = strpos($content, $toSearch) !== false;
                            if ($found) {
                                $replacedContext[$element['value']][$tagName] = $cluster['GalaxyCluster'];
                            }
                        }
                    }
                }
            }
        }

        if ($options['attack']) {
            unset($clusterContain['Galaxy']);
            $attackClusters = $this->GalaxyCluster->find('all', [
                'conditions' => ['GalaxyCluster.galaxy_id' => $mitreAttackGalaxyId],
                'contain' => $clusterContain
            ]);
            foreach ($attackClusters as $cluster) {
                if (strlen($cluster['GalaxyCluster']['value']) > 2) {
                    $cluster['GalaxyCluster']['colour'] = '#0088cc';
                    $tagName = $cluster['GalaxyCluster']['tag_name'];
                    $toSearch = ' ' . $cluster['GalaxyCluster']['value'] . ' ';
                    $found = strpos($content, $toSearch) !== false;
                    if ($found) {
                        $replacedContext[$cluster['GalaxyCluster']['value']][$tagName] = $cluster['GalaxyCluster'];
                    } else {
                        $clusterParts = explode(' - ', $cluster['GalaxyCluster']['value'], 2);
                        $toSearch = ' ' . $clusterParts[0] . ' ';
                        $found = strpos($content, $toSearch) !== false;
                        if ($found) {
                            $replacedContext[$clusterParts[0]][$tagName] = $cluster['GalaxyCluster'];
                        } elseif (isset($clusterParts[1])) {
                            $toSearch = ' ' . $clusterParts[1] . ' ';
                            $found = strpos($content, $toSearch) !== false;
                            if ($found) {
                                $replacedContext[$clusterParts[1]][$tagName] = $cluster['GalaxyCluster'];
                            }
                        }
                    }
                }
            }
        }
        $toReturn = [
            'replacedContext' => $replacedContext
        ];
        if ($options['replace']) {
            // Sort by original value string length, longest values first
            uksort($replacedContext, function ($a, $b) {
                $strlenA = strlen($a);
                $strlenB = strlen($b);
                if ($strlenA === $strlenB) {
                    return 0;
                }
                return ($strlenA < $strlenB) ? 1 : -1;
            });

            $content = $originalContent;
            $secondPassReplace = [];
            // Replace in two pass to prevent double replace
            $id = 0;
            foreach ($replacedContext as $rawText => $replacements) {
                // Replace with first one until a better strategy is found
                reset($replacements);
                $replacement = key($replacements);
                ++$id;
                $content = str_replace($rawText, "@[mark]($id)", $content);
                $secondPassReplace[$id] = "@[tag]($replacement)";
            }

            $content = preg_replace_callback("/@\[mark]\(([^)]*)\)/", function ($matches) use ($secondPassReplace) {
                return $secondPassReplace[$matches[1]];
            }, $content);
            $toReturn['contentWithReplacements'] = $content;
        }
        return $toReturn;
    }

    public function downloadMarkdownFromURL($event_id, $url, $format = 'html')
    {
        $this->Module = ClassRegistry::init('Module');
        $formatMapping = [
            'html' => 'html_to_markdown',
            'pdf' => 'pdf_enrich',
            'pptx' => 'pptx_enrich',
            'xlsx' => 'xlsx_enrich',
            'ods' => 'ods_enrich',
            'odt' => 'odt_enrich',
            'docx' => 'docx_enrich'
        ];
        $module = $this->isFetchURLModuleEnabled($formatMapping[$format]);
        if (!is_array($module)) {
            return false;
        }
        $modulePayload = [
            'module' => $module['name'],
            'event_id' => $event_id
        ];
        if ($format === 'html') {
            $modulePayload['url'] = $url;
        } else {
            $url = filter_var($url, FILTER_SANITIZE_URL);
            $modulePayload['attachment'] = 'temp.foo';
            $modulePayload['data'] = base64_encode(file_get_contents($url));
        }
        if (!empty($module)) {
            $result = $this->Module->queryModuleServer($modulePayload, false, 'Enrichment', false, []);
            if ($format === 'html') {
                if (empty($result['results'][0]['values'][0])) {
                    return '';
                }
                return $result['results'][0]['values'][0];
            } else {
                if (empty($result['results'][0]['values'])) {
                    return '';
                }
                return $result['results'][0]['values'];
            }
        }
        return false;
    }

    public function isFetchURLModuleEnabled($moduleName = 'html_to_markdown') {
        $this->Module = ClassRegistry::init('Module');
        $module = $this->Module->getEnabledModule($moduleName, 'expansion');
        return !empty($module) ? $module : false;
    }

    /**
     * findValidReplacementTag Search if tagName is in content
     *
     * @param  string $content
     * @param  string $tagName
     * @return bool
     */
    private function isValidReplacementTag($content, $tagName)
    {
        $toSearch = !str_contains($tagName, ':') ? ' ' . $tagName . ' ' : $tagName;
        return str_contains($content, $toSearch);
    }

    public function attachTagsAfterReplacements($user, $replacedContext, $eventId)
    {
        $this->EventTag = ClassRegistry::init('EventTag');
        foreach ($replacedContext as $rawText => $tagNames) {
            // Replace with first one until a better strategy is found
            reset($tagNames);
            $tagName = key($tagNames);
            $tagId = $this->EventTag->Tag->lookupTagIdFromName($tagName);
            if ($tagId === -1) {
                $tagId = $this->EventTag->Tag->captureTag(['name' => $tagName], $user);
            }
            $this->EventTag->attachTagToEvent($eventId, ['id' => $tagId]);
        }
    }

    public function getReportFromEvent($user, $options)
    {
        App::uses('ReportFromEvent', 'EventReport');
        $reportGenerator = new ReportFromEvent();
        $reportGenerator->construct($this->Event, $user, $options);
        $report = $reportGenerator->generate();
        return $report;
    }

    public function sendToLLM($report, $user, &$errors)
    {
        $syncTool = new SyncTool();
        $config = [];
        $HttpSocket = $syncTool->setupHttpSocket($config, $this->timeout);
        $LLMFeatureEnabled = Configure::read('Plugin.CTIInfoExtractor_enable', false);
        $url = Configure::read('Plugin.CTIInfoExtractor_url');
        $apiKey = Configure::read('Plugin.CTIInfoExtractor_authentication');
        if (!$LLMFeatureEnabled || empty($url)) {
            $errors[] = __('LLM Feature disabled or no URL provided');
            return false;
        }
        $reportContent = $report['EventReport']['content'];
        $data = json_encode(['text' => $reportContent]);
        $version = implode('.', $this->Event->checkMISPVersion());
        $request = [
            'header' => array_merge([
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'MISP ' . $version . (empty($commit) ? '' : ' - #' . $commit),
                'x-api-key' => $apiKey,
            ])
        ];
        
        $response = $HttpSocket->post($url, $data, $request);
        if (!$response->isOk()) {
            $errors[] = __('LLM server failed to process the request, code: %s.', $response->code);
            return false;
        }
        $data = json_decode($response->body, true);
        if (!empty($data['error'])) {
            $errors[] = $data['error'];
            return false;
        }
/*
        debug($data);
        
        $data = array(
	'AI_ThreatActor' => 'Sofacy',
	'AI_AttributedCountry' => 'unknown',
	'AI_Type' => 'Developments in IT Security',
	'AI_Motivation' => 'Espionage',
	'AI_ExecutiveSummary' => 'The Sofacy group, also known as APT28 or Fancy Bear, continues to target government and strategic organizations primarily in North America and Europe. They have recently been using a tool called Zebrocy, delivered via phishing attacks, to cast a wider net within target organizations. They have also been observed leveraging the Dynamic Data Exchange (DDE) exploit technique to deliver different payloads, including the Koadic toolkit. This report provides details on the campaigns and tactics used by the Sofacy group.',
	'AI_CouldWeBeAffected' => true
);
*/
        
        if (!empty($data['AI_ExecutiveSummary'])) {
            $report['EventReport']['content'] = '# Executive Summary' . PHP_EOL . $data['AI_ExecutiveSummary'] . PHP_EOL . PHP_EOL . '# Report' . PHP_EOL . $report['EventReport']['content'];
        }
        $this->save($report);
        $event = $this->Event->find('first', [
            'conditions' => ['Event.id' => $report['EventReport']['event_id']],
            'recursive' => -1
        ]);
        if (!empty($data['AI_ThreatActor'])) {
            $tag_id = $this->Event->EventTag->Tag->captureTag(['name' => 'misp-galaxy:threat-actor="' . $data['AI_ThreatActor'] . '"'], $user);
            $this->Event->EventTag->attachTagToEvent($event['Event']['id'], ['id' => $tag_id]);
        }

        if (!empty($data['AI_AttributedCountry'])) {
            $tag_id = $this->Event->EventTag->Tag->captureTag(['name' => 'misp-galaxy:threat-actor-country="' . $data['AI_AttributedCountry'] . '"'], $user);
            $this->Event->EventTag->attachTagToEvent($event['Event']['id'], ['id' => $tag_id]);
        }

        if (!empty($data['AI_Motivation'])) {
            $tag_id = $this->Event->EventTag->Tag->captureTag(['name' => 'misp-galaxy:threat-actor-motivation="' . $data['AI_Motivation'] . '"'], $user);
            $this->Event->EventTag->attachTagToEvent($event['Event']['id'], ['id' => $tag_id]);
        }
        return $report;
    }
}
