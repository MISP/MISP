<?php
App::uses('AppModel', 'Model');

class EventReport extends AppModel
{
    public $actsAs = array('Containable');

    public $validate = array(
        'event_id' => array(
            'numeric' => array(
                'rule' => array('numeric')
            )
        ),
        'uuid' => array(
            'uuid' => array(
                'rule' => array('custom', '/^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/'),
                'message' => 'Please provide a valid UUID'
            ),
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'The UUID provided is not unique',
                'required' => 'create'
            )
        ),
        'distribution' => array(
            'rule' => array('inList', array('0', '1', '2', '3', '4', '5')),
            'message' => 'Options: Your organisation only, This community only, Connected communities, All communities, Sharing group, Inherit event',
            'required' => true
        ),
        'value' => array(
            'stringNotEmpty' => array(
                'rule' => array('stringNotEmpty')
            ),
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
        parent::beforeValidate();
        // generate UUID if it doesn't exist
        if (empty($this->data['EventReport']['uuid'])) {
            $this->data['EventReport']['uuid'] = CakeText::uuid();
        }
        // generate timestamp if it doesn't exist
        if (empty($this->data['EventReport']['timestamp'])) {
            $date = new DateTime();
            $this->data['EventReport']['timestamp'] = $date->getTimestamp();
        }
        if ($this->data['EventReport']['distribution'] != 4) {
            $this->data['EventReport']['sharing_group_id'] = 0;
        }
        // Set defaults for when some of the mandatory fields don't have defaults
        // These fields all have sane defaults either based on another field, or due to server settings
        if (!isset($this->data['EventReport']['distribution'])) {
            $this->data['EventReport']['distribution'] = Configure::read('MISP.default_attribute_distribution');
        }
        return true;
    }

    // Gets a report then save it.
    public function captureReport($user, $report)
    {
        $this->Log = ClassRegistry::init('Log');
        $errors = array();
        $report = $this->captureSG($user, $report);
        $this->create();
        $saveSuccess = $this->save($report);
        if (!$saveSuccess) {
            $this->Log->create();
            $this->Log->save(array(
                    'org' => $user['Organisation']['name'],
                    'model' => 'EventReport',
                    'model_id' => 0,
                    'email' => $user['email'],
                    'action' => 'add',
                    'user_id' => $user['id'],
                    'title' => 'Event Report dropped due to validation for Event ' . $report['EventReport']['event_id'] . ' failed: ' . $report['EventReport']['name'],
                    'change' => 'Validation errors: ' . json_encode($this->validationErrors) . ' Full Report: ' . json_encode($report['EventReport']),
            ));
        }
        if (!empty($this->validationErrors)) {
            foreach($this->validationErrors as $validationError) {
                $errors[] = $validationError[0];
            }
        }
        return $errors;
    }

    public function editReport($user, $report, $fromPull = false)
    {
        $errors = array();
        $permissionCheck = $this->canEditReport($user, $report);
        if ($permissionCheck !== true) {
            $errors[] = $permissionCheck;
        }
        if (!empty($errors)) {
            return $errors;
        }
        if (!$fromPull) {
            unset($report['EventReport']['timestamp']);
        }
        $fieldList = array('name', 'content', 'timestamp', 'distribution', 'sharing_group_id', 'deleted');
        $saveSuccess = $this->save($report, array('fieldList' => $fieldList));
        return $errors;
    }

    private function captureSG($user, $report)
    {
        if (isset($report['EventReport']['distribution']) && $report['EventReport']['distribution'] == 4) {
            $report['EventReport'] = $this->Event->__captureSGForElement($report['EventReport'], $user);
        }
        return $report;
    }

    public function buildConditions($user)
    {
        $this->Event = ClassRegistry::init('Event');
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->Event->cacheSgids($user, true);
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
     * fetchById Simple ACL-aware method to fetch a report by Id or UUID
     *
     * @param  array $user
     * @param  int|string $reportId
     * @param  bool  $full
     * @return array
     */
    public function simpleFetchById(array $user, $reportId, $throwErrors=true, $full=false)
    {
        if (Validation::uuid($reportId)) {
            $temp = $this->find('first', array(
                'recursive' => -1,
                'fields' => array("EventReport.id", "EventReport.uuid"),
                'conditions' => array("EventReport.uuid" => $reportId)
            ));
            if (empty($temp)) {
                if ($throwErrors) {
                    throw new NotFoundException(__('Invalid report'));
                }
                return array();
            }
            $reportId = $temp['EventReport']['id'];
        } elseif (!is_numeric($reportId)) {
            if ($throwErrors) {
                throw new NotFoundException(__('Invalid report'));
            }
            return array();
        }
        $options = array('conditions' => array("EventReport.id" => $reportId));
        $report = $this->fetchReports($user, $options, $full=$full);
        return $report;
    }

    public function fetchReports($user, $options = array(), $full=false)
    {
        $params = array(
            'conditions' => $this->buildConditions($user),
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
                if ($throwErrors) {
                    throw new NotFoundException($message);
                }
                return array('authorized' => false, 'error' => $message);
            }
            $report = $report[0];
        }
        if ($user['Role']['perm_site_admin']) {
            return $report;
        }

        if (in_array('view', $authorizations) && count($authorizations) == 1) {
            return $report;
        } else {
            if (in_array('edit', $authorizations) || in_array('delete', $authorizations)) {
                $checkResult = $this->canEditReport($user, $report);
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

    public function canEditReport($user, $report)
    {
        if ($user['Role']['perm_site_admin']) {
            return true;
        } elseif ($report['EventReport']['orgc_id'] != $user['org_id']) {
            $message = __('Only the creator organisation can modify the galaxy report');
            return $message;
        }
        return true;
    }

    public function getProxyMISPElements($user, $eventid)
    {
        $event = $this->Event->fetchEvent($user, ['eventid' => $eventid]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event'));
        }
        $event = $event[0];
        $objects = [];
        $templateConditions = [];
        $recordedConditions = [];
        foreach ($event['Object'] as $k => $object) {
            $objects[$object['id']] = $object;
            $uniqueCondition = sprintf('%s.%s', $object['template_uuid'], $object['template_version']);
            if (!isset($recordedConditions[$uniqueCondition])) {
                $templateConditions['OR'][] = [
                    'ObjectTemplate.uuid' => $object['template_uuid'],
                    'ObjectTemplate.version' => $object['template_version']
                ];
                $recordedConditions[$uniqueCondition] = true;
            }
        }
        $this->ObjectTemplate = ClassRegistry::init('ObjectTemplate');
        $templates = $this->ObjectTemplate->find('all', array(
            'conditions' => $templateConditions,
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
            $objectTemplates[sprintf('%s.%s', $template['ObjectTemplate']['uuid'], $template['ObjectTemplate']['version'])] = $template;
        }
        $proxyMISPElements = [
            'attribute' => Hash::combine($event, 'Attribute.{n}.id', 'Attribute.{n}'),
            'object' => $objects,
            'objectTemplates' => $objectTemplates
        ];
        return $proxyMISPElements;
    }
}
