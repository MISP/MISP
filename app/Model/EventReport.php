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

    // very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
    // options:
    //     fields
    //     contain
    //     conditions
    //     order
    //     group
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
        if (!$user['Role']['perm_modify'] && !$user['Role']['perm_site_admin']) {
            $errors[] = __('Incorrect permission');
        }
        if (empty($errors)) {
            $date = new DateTime();
            if (!$fromPull) {
                unset($report['EventReport']['timestamp']);
            }
        }
        $fieldList = array('name', 'content', 'timestamp', 'distribution', 'sharing_group_id', 'deleted');
        // $saveSuccess = $this->save($report, array('fieldList' => $fieldList));
        return $errors;
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

    private function captureSG($user, $report)
    {
        if (isset($report['EventReport']['distribution']) && $report['EventReport']['distribution'] == 4) {
            $report['EventReport'] = $this->Event->__captureSGForElement($report['EventReport'], $user);
        }
        return $report;
    }
}
