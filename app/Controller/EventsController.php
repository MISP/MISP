<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

/**
 * @property Event $Event
 * @property User $User
 */
class EventsController extends AppController
{
    public $components = array(
        'RequestHandler',
        'IOCImport',
    );

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
        'order' => array(
            'Event.timestamp' => 'DESC'
        ),
        'contain' => array(
            'Org' => array('fields' => array('id', 'name', 'uuid')),
            'Orgc' => array('fields' => array('id', 'name', 'uuid')),
            'SharingGroup' => array('fields' => array('id', 'name', 'uuid'))
        )
    );

    // private
    const ACCEPTED_FILTERING_NAMED_PARAMS = array(
        'sort', 'direction', 'focus', 'extended', 'overrideLimit', 'filterColumnsOverwrite', 'attributeFilter', 'page',
        'searchFor', 'proposal', 'correlation', 'warning', 'deleted', 'includeRelatedTags', 'includeDecayScore', 'distribution',
        'taggedAttributes', 'galaxyAttachedAttributes', 'objectType', 'attributeType', 'feed', 'server', 'toIDS',
        'sighting', 'includeSightingdb', 'warninglistId', 'correlationId', 'email', 'eventid', 'datefrom', 'dateuntil'
    );

    // private
    const DEFAULT_FILTERING_RULE = array(
        'searchFor' => '',
        'attributeFilter' => 'all',
        'proposal' => 0,
        'correlation' => 0,
        'warning' => 0,
        'deleted' => 0,
        'includeRelatedTags' => 0,
        'includeDecayScore' => 0,
        'toIDS' => 0,
        'feed' => 0,
        'server' => 0,
        'distribution' => array(0, 1, 2, 3, 4, 5),
        'sighting' => 0,
        'taggedAttributes' => '',
        'galaxyAttachedAttributes' => '',
        'warninglistId' => '',
        'correlationId' => '',
    );

    // private
    const DEFAULT_HIDDEN_INDEX_COLUMNS = [
        'timestamp',
        'publish_timestamp'
    ];

    public function beforeFilter()
    {
        parent::beforeFilter();

        $this->Security->unlockedActions[] = 'viewEventAttributes';

        // if not admin or own org, check private as well..
        if (!$this->_isSiteAdmin() && in_array($this->request->action, ['index', 'proposalEventIndex'], true)) {
            $conditions = $this->Event->createEventConditions($this->Auth->user());
            if ($this->userRole['perm_sync'] && $this->Auth->user('Server')['push_rules']) {
                $conditions['AND'][] = $this->Event->filterRulesToConditions($this->Auth->user('Server')['push_rules']);
            }
            $this->paginate = Set::merge($this->paginate, array('conditions' => $conditions));
        }

        if (in_array($this->request->action, ['checkLocks', 'getDistributionGraph'], true)) {
            $this->Security->doNotGenerateToken = true;
        }

        if (Configure::read('Plugin.CustomAuth_enable') && in_array($this->request->action, ['saveFreeText'], true)) {
            $this->Security->csrfCheck = false;
        }
    }

    /**
     * @param string $value
     * @return array[]
     */
    private function __filterOnAttributeValue($value)
    {
        // dissect the value
        $include = array();
        $exclude = array();
        $includeIDs = [];
        $excludeIDs = [];
        if (!empty($value)) {
            if (!is_array($value)) {
                $pieces = explode('|', mb_strtolower($value));
            } else {
                $pieces = $value;
            }

            foreach ($pieces as $piece) {
                if ($piece[0] === '!') {
                    $exclude[] =  '%' . substr($piece, 1) . '%';
                } else {
                    $include[] = "%$piece%";
                }
            }

            if (!empty($include)) {
                $includeConditions = [];
                foreach ($include as $i) {
                    $includeConditions['OR'][] = array('Attribute.value1 LIKE' => $i);
                    $includeConditions['OR'][] = array('Attribute.value2 LIKE' => $i);
                }

                $includeIDs = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array(
                    'conditions' => $includeConditions,
                    'flatten' => true,
                    'event_ids' => true,
                    'list' => true,
                ));
            }

            if (!empty($exclude)) {
                $excludeConditions = [];
                foreach ($exclude as $e) {
                    $excludeConditions['OR'][] = array('Attribute.value1 LIKE' => $e);
                    $excludeConditions['OR'][] = array('Attribute.value2 LIKE' => $e);
                }

                $excludeIDs = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array(
                    'conditions' => $excludeConditions,
                    'flatten' => true,
                    'event_ids' => true,
                    'list' => true,
                ));
            }
        }
        // return -1 as the only value in includedIDs if both arrays are empty. This will mean that no events will be shown if there was no hit
        if (empty($includeIDs) && empty($excludeIDs)) {
            $includeIDs[] = -1;
        }
        return array($includeIDs, $excludeIDs);
    }

    /**
     * @param string|array $value
     * @return array Event ID that match filter
     */
    private function __quickFilter($value)
    {
        if (!is_array($value)) {
            $value = array($value);
        }
        $values = array();
        foreach ($value as $v) {
            $values[] = '%' . mb_strtolower($v) . '%';
        }

        // get all of the attributes that have a hit on the search term, in either the value or the comment field
        // This is not perfect, the search will be case insensitive, but value1 and value2 are searched separately. lower() doesn't seem to work on virtualfields
        $subconditions = array();
        foreach ($values as $v) {
            $subconditions[] = array('Attribute.value1 LIKE' => $v);
            $subconditions[] = array('Attribute.value2 LIKE' => $v);
            $subconditions[] = array('Attribute.comment LIKE' => $v);
        }
        $conditions = array(
            'OR' => $subconditions,
        );
        $result = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array(
            'conditions' => $conditions,
            'flatten' => 1,
            'event_ids' => true,
            'list' => true,
        ));

        // we now have a list of event IDs that match on an attribute level, and the user can see it. Let's also find all of the events that match on other criteria!
        // What is interesting here is that we no longer have to worry about the event's releasability. With attributes this was a different case,
        // because we might run into a situation where a user can see an event but not a specific attribute
        // returning a hit on such an attribute would allow users to enumerate hidden attributes
        // For anything beyond this point the default pagination restrictions will apply!

        // First of all, there are tags that might be interesting for us
        $subconditions = array();
        foreach ($values as $v) {
            $subconditions[] = array('lower(name) LIKE' => $v);
        }
        $tags = $this->Event->EventTag->Tag->find('all', array(
            'conditions' => $subconditions,
            'fields' => array('id'),
            'contain' => array('EventTag' => ['fields' => 'event_id'], 'AttributeTag' => ['fields' => 'event_id']),
        ));
        foreach ($tags as $tag) {
            foreach ($tag['EventTag'] as $eventTag) {
                if (!in_array($eventTag['event_id'], $result)) {
                    $result[] = $eventTag['event_id'];
                }
            }
            foreach ($tag['AttributeTag'] as $attributeTag) {
                if (!in_array($attributeTag['event_id'], $result)) {
                    $result[] = $attributeTag['event_id'];
                }
            }
        }

        // Finally, let's search on the event metadata!
        $subconditions = array();
        foreach ($values as $v) {
            $subconditions[] = array('lower(name) LIKE' => $v);
        }
        $orgs = $this->Event->Org->find('column', array(
            'conditions' => $subconditions,
            'fields' => array('Org.id')
        ));

        $conditions = empty($result) ? [] : ['NOT' => ['id' => $result]]; // Do not include events that we already found
        foreach ($values as $v) {
            $conditions['OR'][] = array('lower(info) LIKE' => $v);
            $conditions['OR'][] = array('lower(uuid) LIKE' => $v);
        }
        if (!empty($orgs)) {
            $conditions['OR']['orgc_id'] = $orgs;
        }
        $otherEvents = $this->Event->find('column', array(
            'fields' => array('Event.id'),
            'conditions' => $conditions,
        ));
        foreach ($otherEvents as $eventId) {
            $result[] = $eventId;
        }
        return $result;
    }

    /**
     * @param array $passedArgs
     * @param string $urlparams
     * @param bool $nothing True when nothing should be fetched from database
     * @return array
     */
    private function __setIndexFilterConditions(array $passedArgs, &$urlparams, &$nothing = false)
    {
        $passedArgsArray = array();
        foreach ($passedArgs as $k => $v) {
            if (substr($k, 0, 6) !== 'search') {
                continue;
            }
            if (!is_array($v)) {
                if ($urlparams != "") {
                    $urlparams .= "/";
                }
                $urlparams .= $k . ":" . $v;
            }
            $searchTerm = strtolower(substr($k, 6));
            switch ($searchTerm) {
                case 'all':
                    if (!empty($v)) {
                        $this->paginate['conditions']['AND'][] = array('Event.id' => $this->__quickFilter($v));
                    }
                    break;
                case 'attribute':
                    $event_id_arrays = $this->__filterOnAttributeValue($v);
                    if (!empty($event_id_arrays[0])) {
                        $this->paginate['conditions']['AND'][] = array('Event.id' => $event_id_arrays[0]);
                    }
                    if (!empty($event_id_arrays[1])) {
                        $this->paginate['conditions']['AND'][] = array('Event.id !=' => $event_id_arrays[1]);
                    }
                    break;
                case 'published':
                    if ($v === 2 || $v === '2') { // both
                        continue 2;
                    }
                    if (is_array($v) && in_array(0, $v) && in_array(1, $v)) {
                        continue 2; // both
                    }
                    $this->paginate['conditions']['AND'][] = array('Event.published' => $v);
                    break;
                case 'hasproposal':
                    if ($v === 2 || $v === '2') { // both
                        continue 2;
                    }
                    $proposalQuery = "exists (select id, deleted from shadow_attributes where shadow_attributes.event_id = Event.id and shadow_attributes.deleted = 0)";
                    if ($v == 0) {
                        $proposalQuery = 'not ' . $proposalQuery;
                    }
                    $this->paginate['conditions']['AND'][] = $proposalQuery;
                    break;
                case 'eventid':
                    if ($v == "") {
                        continue 2;
                    }
                    $pieces = is_array($v) ? $v : explode('|', $v);
                    $eventidConditions = array();
                    foreach ($pieces as $piece) {
                        $piece = trim($piece);
                        if ($piece[0] === '!') {
                            if (strlen($piece) === 37) {
                                $eventidConditions['NOT']['uuid'][] = substr($piece, 1);
                            } else {
                                $eventidConditions['NOT']['id'][] = substr($piece, 1);
                            }
                        } else {
                            if (strlen($piece) === 36) {
                                $eventidConditions['OR']['uuid'][] = $piece;
                            } else {
                                $eventidConditions['OR']['id'][] = $piece;
                            }
                        }
                    }
                    foreach ($eventidConditions as $operator => $conditionForOperator) {
                        foreach ($conditionForOperator as $conditionKey => $conditionValue) {
                            $lookupKey = 'Event.' . $conditionKey;
                            if ($operator === 'NOT') {
                                $lookupKey = $lookupKey . ' !=';
                            }
                            $this->paginate['conditions']['AND'][] = array($lookupKey => $conditionValue);
                        }
                    }
                    break;
                case 'datefrom':
                    if ($v == "") {
                        continue 2;
                    }
                    $this->paginate['conditions']['AND'][] = array('Event.date >=' => $v);
                    break;
                case 'dateuntil':
                    if ($v == "") {
                        continue 2;
                    }
                    $this->paginate['conditions']['AND'][] = array('Event.date <=' => $v);
                    break;
                case 'timestamp':
                    if ($v == "") {
                        continue 2;
                    }
                    if (is_array($v) && isset($v[0]) && isset($v[1])) {
                        if (!is_int($v[0])) {
                            $v[0] = $this->Event->resolveTimeDelta($v[0]);
                        }
                        if (!is_int($v[1])) {
                            $v[1] = $this->Event->resolveTimeDelta($v[1]);
                        }
                        $this->paginate['conditions']['AND'][] = array('Event.timestamp >=' => $v[0]);
                        $this->paginate['conditions']['AND'][] = array('Event.timestamp <=' => $v[1]);
                    } else {
                        if (!is_int($v)) {
                            $v = $this->Event->resolveTimeDelta($v);
                        }
                        $this->paginate['conditions']['AND'][] = array('Event.timestamp >=' => $v);
                    }
                    break;
                case 'publish_timestamp':
                case 'publishtimestamp':
                    if ($v == "") {
                        continue 2;
                    }
                    if (is_array($v) && isset($v[0]) && isset($v[1])) {
                        if (!is_int($v[0])) {
                            $v[0] = $this->Event->resolveTimeDelta($v[0]);
                        }
                        if (!is_int($v[1])) {
                            $v[1] = $this->Event->resolveTimeDelta($v[1]);
                        }
                        $this->paginate['conditions']['AND'][] = array('Event.publish_timestamp >=' => $v[0]);
                        $this->paginate['conditions']['AND'][] = array('Event.publish_timestamp <=' => $v[1]);
                    } else {
                        if (!is_int($v)) {
                            $v = $this->Event->resolveTimeDelta($v);
                        }
                        $this->paginate['conditions']['AND'][] = array('Event.publish_timestamp >=' => $v);
                    }
                    break;
                case 'org':
                    if ($v == "" || !Configure::read('MISP.showorg')) {
                        continue 2;
                    }

                    $this->Event->Org->virtualFields = [
                        'upper_name' => 'UPPER(name)',
                        'lower_uuid' => 'LOWER(uuid)',
                    ];
                    $orgs = array_column($this->Event->Org->find('all', [
                        'fields' => ['Org.id', 'Org.upper_name', 'Org.lower_uuid'],
                        'recursive' => -1,
                    ]), 'Org');
                    $this->Event->Org->virtualFields = [];
                    $orgByName = array_column($orgs, 'id', 'upper_name');
                    $orgByUuid = array_column($orgs, 'id', 'lower_uuid');
                    // if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
                    $pieces = is_array($v) ? $v : explode('|', $v);
                    $test = array();
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            $piece = substr($piece, 1); // remove `!` char
                            if (is_numeric($piece)) {
                                $orgId = $piece;
                            } else if (Validation::uuid($piece)) {
                                $orgId = isset($orgByUuid[$piece]) ? $orgByUuid[$piece] : null;
                            } else {
                                $orgName = mb_strtoupper($piece);
                                $orgId = isset($orgByName[$orgName]) ? $orgByName[$orgName] : null;
                            }
                            if ($orgId) {
                                $this->paginate['conditions']['AND'][] = array('Event.orgc_id !=' => $orgId);
                            }
                        } else {
                            if (is_numeric($piece)) {
                                $test['OR'][] = array('Event.orgc_id' => $piece);
                            } else {
                                if (Validation::uuid($piece)) {
                                    $orgId = isset($orgByUuid[$piece]) ? $orgByUuid[$piece] : null;
                                } else {
                                    $orgName = mb_strtoupper($piece);
                                    $orgId = isset($orgByName[$orgName]) ? $orgByName[$orgName] : null;
                                }
                                if ($orgId) {
                                    $test['OR'][] = array('Event.orgc_id' => $orgId);
                                } else {
                                    $nothing = true;
                                }
                            }
                        }
                    }
                    $this->paginate['conditions']['AND'][] = $test;
                    break;
                case 'sharinggroup':
                    $pieces = explode('|', $v);
                    $test = array();
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            $this->paginate['conditions']['AND'][] = array('Event.sharing_group_id !=' => substr($piece, 1));
                        } else {
                            $test['OR'][] = array('Event.sharing_group_id' => $piece);
                        }
                    }
                    if (!empty($test)) {
                        $this->paginate['conditions']['AND'][] = $test;
                    }
                    break;
                case 'eventinfo':
                    if ($v == "") {
                        continue 2;
                    }
                    // if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
                    $pieces = explode('|', $v);
                    $test = array();
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            $this->paginate['conditions']['AND'][] = array('lower(Event.info) NOT LIKE' => '%' . mb_strtolower(substr($piece, 1)) . '%');
                        } else {
                            $test['OR'][] = array('lower(Event.info) LIKE' => '%' . mb_strtolower($piece) . '%');
                        }
                    }
                    $this->paginate['conditions']['AND'][] = $test;
                    break;
                case 'tag':
                case 'tags':
                    if (!$v || !Configure::read('MISP.tagging') || $v === 0) {
                        continue 2;
                    }
                    $pieces = is_array($v) ? $v : explode('|', $v);
                    $isANDed = false;
                    if (count($pieces) == 1 && strpos($pieces[0], '&') !== false) {
                        $pieces = explode('&', $pieces[0]);
                        $isANDed = count($pieces) > 1;
                    }
                    $filterString = "";
                    $expectOR = false;
                    $tagRules = [];
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            if (is_numeric(substr($piece, 1))) {
                                $conditions = array('Tag.id' => substr($piece, 1));
                            } else {
                                $conditions = array('Tag.name' => substr($piece, 1));
                            }
                            $tagName = $this->Event->EventTag->Tag->find('first', array(
                                'conditions' => $conditions,
                                'fields' => array('id', 'name'),
                                'recursive' => -1,
                            ));

                            if (empty($tagName)) {
                                if ($filterString != "") {
                                    $filterString .= "|";
                                }
                                $filterString .= '!' . $piece;
                                continue;
                            }
                            $tagRules['block'][] = $tagName['Tag']['id'];
                            if ($filterString != "") {
                                $filterString .= "|";
                            }
                            $filterString .= '!' . $tagName['Tag']['name'];
                        } else {
                            $expectOR = true;
                            if (is_numeric($piece)) {
                                $conditions = array('Tag.id' => $piece);
                            } else {
                                $conditions = array('Tag.name' => $piece);
                            }
                            $tagName = $this->Event->EventTag->Tag->find('first', array(
                                'conditions' => $conditions,
                                'fields' => array('id', 'name'),
                                'recursive' => -1,
                            ));
                            if (empty($tagName)) {
                                if ($filterString != "") {
                                    $filterString .= "|";
                                }
                                $filterString .= $piece;
                                continue;
                            }
                            $tagRules['include'][] = $tagName['Tag']['id'];
                            if ($filterString != "") {
                                $filterString .= "|";
                            }
                            $filterString .= $tagName['Tag']['name'];
                        }
                    }

                    if (!empty($tagRules['block'])) {
                        $block = $this->Event->EventTag->find('column', array(
                            'conditions' => array('EventTag.tag_id' => $tagRules['block']),
                            'fields' => ['EventTag.event_id'],
                        ));
                        if (!empty($block)) {
                            $this->paginate['conditions']['AND'][] = 'Event.id NOT IN (' . implode(",", $block) . ')';
                        }
                    }

                    if (!empty($tagRules['include'])) {
                        if ($isANDed) {
                            $include = $this->Event->EventTag->find('column', array(
                                'conditions' => ['EventTag.tag_id' => $tagRules['include']],
                                'fields' => ['EventTag.event_id'],
                                'group' => ['EventTag.event_id'],
                                'having' => ['COUNT(*) =' => count($tagRules['include'])],
                            ));
                        } else {
                            $include = $this->Event->EventTag->find('column', array(
                                'conditions' => array('EventTag.tag_id' => $tagRules['include']),
                                'fields' => ['EventTag.event_id'],
                            ));
                        }
                        if (!empty($include)) {
                            $this->paginate['conditions']['AND'][] = 'Event.id IN (' . implode(",", $include) . ')';
                        } else {
                            $nothing = true;
                        }
                    } else if ($expectOR) {
                        // If we have a list of OR-d arguments, we expect to end up with a list of allowed event IDs
                        // If we don't however, it means that none of the tags was found. To prevent displaying the entire event index in this case:
                        $nothing = true;
                    }

                    $v = $filterString;
                    break;
                case 'email':
                    if ($v == "") {
                        continue 2;
                    }

                    if (!$this->_isSiteAdmin()) {
                        // Special case to filter own events
                        if (strtolower($this->Auth->user('email')) === strtolower(trim($v))) {
                            $this->paginate['conditions']['AND'][] = ['Event.user_id' => $this->Auth->user('id')];
                            break;
                        } else {
                            $nothing = true;
                            continue 2;
                        }
                    }

                    // if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
                    $pieces = explode('|', $v);
                    $usersToMatch = array();
                    $positiveQuery = false;
                    foreach ($pieces as $piece) {
                        if ($piece[0] === '!') {
                            $users = $this->Event->User->find('column', array(
                                'fields' => array('User.id'),
                                'conditions' => array('User.email LIKE' => '%' . strtolower(substr($piece, 1)) . '%')
                            ));
                            if (!empty($users)) {
                                $this->paginate['conditions']['AND'][] = array('Event.user_id !=' => $users);
                            }
                        } else {
                            $positiveQuery = true;
                            $users = $this->Event->User->find('column', array(
                                'fields' => array('User.id'),
                                'conditions' => array('User.email LIKE' => '%' . strtolower($piece) . '%')
                            ));
                            $usersToMatch = array_merge($usersToMatch, $users);
                        }
                    }

                    if ($positiveQuery) {
                        if (empty($usersToMatch)) {
                            $nothing = true;
                        } else {
                            $this->paginate['conditions']['AND'][] = ['Event.user_id' => array_unique($usersToMatch, SORT_REGULAR)];
                        }
                    }
                    break;
                case 'distribution':
                case 'analysis':
                case 'threatlevel':
                    if ($v == "") {
                        continue 2;
                    }
                    $filterString = "";
                    $searchTermInternal = $searchTerm;
                    if ($searchTerm === 'threatlevel') {
                        $searchTermInternal = 'threat_level_id';
                        $terms = $this->Event->ThreatLevel->listThreatLevels();
                    } elseif ($searchTerm === 'analysis') {
                        $terms = $this->Event->analysisLevels;
                    } else {
                        $terms = $this->Event->distributionLevels;
                    }
                    $pieces = is_array($v) ? $v : explode('|', $v);
                    $test = array();
                    foreach ($pieces as $piece) {
                        if ($filterString != "") {
                            $filterString .= '|';
                        }
                        if ($piece[0] === '!') {
                            $filterString .= $terms[substr($piece, 1)];
                            $this->paginate['conditions']['AND'][] = array('Event.' . $searchTermInternal . ' !=' => substr($piece, 1));
                        } else {
                            $filterString .= $terms[$piece];
                            $test['OR'][] = array('Event.' . $searchTermInternal => $piece);
                        }
                    }
                    $this->paginate['conditions']['AND'][] = $test;
                    $v = $filterString;
                    break;
                case 'minimal':
                    $tableName = $this->Event->EventReport->table;
                    $eventReportQuery = sprintf('EXISTS (SELECT id FROM %s WHERE %s.event_id = Event.id AND %s.deleted = 0)', $tableName, $tableName, $tableName);
                    $this->paginate['conditions']['AND'][] = [
                        'OR' => [
                            ['Event.attribute_count >' => 0],
                            [$eventReportQuery]
                        ]
                    ];
                    break;
                case 'value':
                    if ($v == "") {
                        continue 2;
                    }
                    $conditions['OR'] = [
                        ['Attribute.value1' => $v],
                        ['Attribute.value2' => $v],
                    ];

                    $eventIds = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array(
                        'conditions' => $conditions,
                        'flatten' => true,
                        'event_ids' => true,
                        'list' => true,
                    ));

                    $this->paginate['conditions']['AND'][] = array('Event.id' => $eventIds);

                    break;
                default:
                    continue 2;
            }
            $passedArgsArray[$searchTerm] = $v;
        }
        return $passedArgsArray;
    }

    public function index()
    {
        // list the events
        $urlparams = "";
        $overrideAbleParams = array('all', 'attribute', 'published', 'eventid', 'datefrom', 'dateuntil', 'org', 'eventinfo', 'tag', 'tags', 'distribution', 'sharinggroup', 'analysis', 'threatlevel', 'email', 'hasproposal', 'timestamp', 'publishtimestamp', 'publish_timestamp', 'minimal', 'value');
        $paginationParams = array('limit', 'page', 'sort', 'direction', 'order');
        $passedArgs = $this->passedArgs;
        if (!empty($this->request->data)) {
            if (isset($this->request->data['request'])) {
                $this->request->data = $this->request->data['request'];
            }
            foreach ($this->request->data as $k => $v) {
                if (str_starts_with($k, 'search') && in_array(strtolower(substr($k, 6)), $overrideAbleParams, true)) {
                    unset($this->request->data[$k]);
                    $this->request->data[strtolower(substr($k, 6))] = $v;
                } else if (in_array(strtolower($k), $overrideAbleParams, true)) {
                    unset($this->request->data[$k]);
                    $this->request->data[strtolower($k)] = $v;
                }
            }
            foreach ($overrideAbleParams as $oap) {
                if (isset($this->request->data[$oap])) {
                    $passedArgs['search' . $oap] = $this->request->data[$oap];
                }
            }
            foreach ($paginationParams as $paginationParam) {
                if (isset($this->request->data[$paginationParam])) {
                    $passedArgs[$paginationParam] = $this->request->data[$paginationParam];
                }
            }
        }

        // check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
        $nothing = false;
        $passedArgsArray = $this->__setIndexFilterConditions($passedArgs, $urlparams, $nothing);
        $this->loadModel('GalaxyCluster');

        // for REST, don't use the pagination. With this, we'll escape the limit of events shown on the index.
        if ($this->_isRest()) {
            if ($nothing) {
                return $this->RestResponse->viewData([], $this->response->type(), false, false, false, ['X-Result-Count' => 0]);
            }
            return $this->__indexRestResponse($passedArgs);
        }

        $this->paginate['contain']['ThreatLevel'] = [
            'fields' => array('ThreatLevel.name')
        ];
        $this->paginate['contain']['EventTag'] = [
            'fields' => ['EventTag.event_id', 'EventTag.tag_id', 'EventTag.local', 'EventTag.relationship_type'],
        ];
        if ($this->_isSiteAdmin()) {
            $this->paginate['contain'][] = 'User.email';
        }

        if ($nothing) {
            $this->paginate['conditions']['AND'][] = ['Event.id' => -1]; // do not fetch any event
        }
        $this->Event->includeAnalystData = isset($passedArgs['includeAnalystData']) ? $passedArgs['includeAnalystData'] : false;
        $this->paginate['includeAnalystData'] = isset($passedArgs['includeAnalystData']) ? $passedArgs['includeAnalystData'] : false;
        $events = $this->paginate();

        if (count($events) === 1 && isset($this->passedArgs['searchall'])) {
            $this->redirect(array('controller' => 'events', 'action' => 'view', $events[0]['Event']['id']));
        }

        list($possibleColumns, $enabledColumns) = $this->__indexColumns();
        $events = $this->__attachInfoToEvents($enabledColumns, $events);

        $this->__noKeyNotification();
        $this->set('events', $events);
        $this->set('possibleColumns', $possibleColumns);
        $this->set('columns', $enabledColumns);
        $this->set('eventDescriptions', $this->Event->fieldDescriptions);
        $this->set('analysisLevels', $this->Event->analysisLevels);
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->set('shortDist', $this->Event->shortDist);
        $this->set('distributionData', $this->__genDistributionGraph(-1));
        $this->set('urlparams', $urlparams);
        $this->set('passedArgsArray', $passedArgsArray);
        $this->set('passedArgs', json_encode($passedArgs));

        if ($this->request->is('ajax')) {
            $this->autoRender = false;
            $this->layout = false;
            $this->render('ajax/index');
        }
    }

    /**
     * @param array $passedArgs
     * @return CakeResponse
     */
    private function __indexRestResponse(array $passedArgs)
    {
        // We do not want to allow instances to pull our data that can't make sense of protected mode events
        $skipProtected = (
            !empty($this->request->header('misp-version')) &&
            version_compare($this->request->header('misp-version'), '2.4.156') < 0
        );

        $fieldNames = $this->Event->schema();
        $minimal = !empty($passedArgs['searchminimal']) || !empty($passedArgs['minimal']);
        if ($minimal) {
            $rules = [
                'recursive' => -1,
                'fields' => array('id', 'timestamp', 'sighting_timestamp', 'published', 'uuid', 'protected'),
                'contain' => array('Orgc.uuid'),
            ];
        } else {
            // Remove user ID from fetched fields
            unset($fieldNames['user_id']);
            $rules = [
                'contain' => ['EventTag'],
                'fields' => array_keys($fieldNames),
                'includeAnalystData' => isset($passedArgs['includeAnalystData']) ? $passedArgs['includeAnalystData'] : false,
            ];
        }
        if (isset($passedArgs['sort']) && isset($fieldNames[$passedArgs['sort']])) {
            if (isset($passedArgs['direction']) && in_array(strtoupper($passedArgs['direction']), ['ASC', 'DESC'])) {
                $rules['order'] = array('Event.' . $passedArgs['sort'] => $passedArgs['direction']);
            } else {
                $rules['order'] = array('Event.' . $passedArgs['sort'] => 'ASC');
            }
        }
        if (isset($this->paginate['conditions'])) {
            $rules['conditions'] = $this->paginate['conditions'];
        }
        if ($skipProtected) {
            $rules['conditions']['Event.protected'] = 0;
        }
        $paginationRules = array('page', 'limit', 'sort', 'direction', 'order');
        foreach ($paginationRules as $paginationRule) {
            if (isset($passedArgs[$paginationRule])) {
                $rules[$paginationRule] = $passedArgs[$paginationRule];
            }
        }

        if (empty($rules['limit'])) {
            $events = [];
            $i = 1;
            $rules['limit'] = 20000;
            while (true) {
                $rules['page'] = $i++;
                $temp = $this->Event->find('all', $rules);
                $resultCount = count($temp);
                if ($resultCount !== 0) {
                    array_push($events, ...$temp);
                }
                if ($resultCount < $rules['limit']) {
                    break;
                }
            }
            unset($temp);
            $absoluteTotal = count($events);
        } else {
            $counting_rules = $rules;
            unset($counting_rules['limit']);
            unset($counting_rules['page']);
            $absoluteTotal = $this->Event->find('count', $counting_rules);

            $events = $absoluteTotal === 0 ? [] : $this->Event->find('all', $rules);
        }

        $isCsvResponse = $this->response->type() === 'text/csv';

        $protectedEventsByInstanceKey = $this->Event->CryptographicKey->protectedEventsByInstanceKey($events);
        $protectedEventsByInstanceKey = array_flip($protectedEventsByInstanceKey);

        if (!$minimal) {
            // Collect all tag IDs that are events
            $tagIds = [];
            foreach (array_column($events, 'EventTag') as $eventTags) {
                foreach (array_column($eventTags, 'tag_id') as $tagId) {
                    $tagIds[$tagId] = true;
                }
            }

            if (!empty($tagIds)) {
                $tags = $this->Event->EventTag->Tag->find('all', [
                    'conditions' => [
                        'Tag.id' => array_keys($tagIds),
                        'Tag.exportable' => 1,
                    ],
                    'recursive' => -1,
                    'fields' => ['Tag.id', 'Tag.name', 'Tag.colour', 'Tag.is_galaxy'],
                ]);
                unset($tagIds);
                $tags = array_column(array_column($tags, 'Tag'), null, 'id');

                foreach ($events as $k => $event) {
                    if (empty($event['EventTag'])) {
                        continue;
                    }
                    foreach ($event['EventTag'] as $k2 => $et) {
                        if (!isset($tags[$et['tag_id']])) {
                            unset($events[$k]['EventTag'][$k2]); // tag not exists or is not exportable
                        } else {
                            $events[$k]['EventTag'][$k2]['Tag'] = $tags[$et['tag_id']];
                        }
                    }
                    $events[$k]['EventTag'] = array_values($events[$k]['EventTag']);
                }
                if (!$isCsvResponse) {
                    $events = $this->GalaxyCluster->attachClustersToEventIndex($this->Auth->user(), $events, false);
                }
            }

            // Fetch all org and sharing groups that are in events
            $orgIds = [];
            $sharingGroupIds = [];
            foreach ($events as $k => $event) {
                $orgIds[$event['Event']['org_id']] = true;
                $orgIds[$event['Event']['orgc_id']] = true;
                $sharingGroupIds[$event['Event']['sharing_group_id']] = true;
                if ($event['Event']['protected'] && !isset($protectedEventsByInstanceKey[$event['Event']['id']])) {
                    unset($events[$k]);
                }
            }
            $events = array_values($events);
            if (!empty($orgIds)) {
                $orgs = $this->Event->Org->find('all', [
                    'conditions' => ['Org.id' => array_keys($orgIds)],
                    'recursive' => -1,
                    'fields' => $this->paginate['contain']['Org']['fields'],
                ]);
                unset($orgIds);
                $orgs = array_column(array_column($orgs, 'Org'), null, 'id');
            } else {
                $orgs = [];
            }
            unset($sharingGroupIds[0]);
            if (!empty($sharingGroupIds)) {
                $sharingGroups = $this->Event->SharingGroup->find('all', [
                    'conditions' => ['SharingGroup.id' => array_keys($sharingGroupIds)],
                    'recursive' => -1,
                    'fields' => $this->paginate['contain']['SharingGroup']['fields'],
                ]);
                unset($sharingGroupIds);
                $sharingGroups = array_column(array_column($sharingGroups, 'SharingGroup'), null, 'id');
            }
            foreach ($events as $key => $event) {
                $temp = $event['Event'];
                $temp['Org'] = $orgs[$temp['org_id']];
                $temp['Orgc'] = $orgs[$temp['orgc_id']];
                if ($temp['sharing_group_id'] != 0) {
                    $temp['SharingGroup'] = $sharingGroups[$temp['sharing_group_id']];
                }
                $rearrangeObjects = array('GalaxyCluster', 'EventTag');
                foreach ($rearrangeObjects as $ro) {
                    if (isset($event[$ro])) {
                        $temp[$ro] = $event[$ro];
                    }
                }
                $events[$key] = $temp;
            }
            unset($sharingGroups);
            unset($orgs);
            if ($this->response->type() === 'application/xml') {
                $events = array('Event' => $events);
            }
        } else { // minimal
            foreach ($events as $key => $event) {
                if ($event['Event']['protected'] && !isset($protectedEventsByInstanceKey[$event['Event']['id']])) {
                    unset($events[$key]);
                    continue;
                }
                $event['Event']['orgc_uuid'] = $event['Orgc']['uuid'];
                unset($event['Event']['protected']);
                $events[$key] = $event['Event'];
            }
            $events = array_values($events);
        }

        if ($isCsvResponse) {
            App::uses('CsvExport', 'Export');
            $export = new CsvExport();
            $events = $export->eventIndex($events);
        }

        return $this->RestResponse->viewData($events, $this->response->type(), false, false, false, ['X-Result-Count' => $absoluteTotal]);
    }

    private function __indexColumns()
    {
        $possibleColumns = [];

        if ($this->_isSiteAdmin() && !Configure::read('MISP.showorgalternate')) {
            $possibleColumns[] = 'owner_org';
        }

        if (Configure::read('MISP.tagging')) {
            $possibleColumns[] = 'clusters';
            $possibleColumns[] = 'tags';
        }

        $possibleColumns[] = 'attribute_count';

        if (Configure::read('MISP.showCorrelationsOnIndex')) {
            $possibleColumns[] = 'correlations';
        }

        if (Configure::read('MISP.showEventReportCountOnIndex')) {
            $possibleColumns[] = 'report_count';
        }

        if (Configure::read('MISP.showSightingsCountOnIndex')) {
            $possibleColumns[] = 'sightings';
        }

        if (Configure::read('MISP.showProposalsCountOnIndex')) {
            $possibleColumns[] = 'proposals';
        }

        if (Configure::read('MISP.showDiscussionsCountOnIndex') && !Configure::read('MISP.discussion_disable')) {
            $possibleColumns[] = 'discussion';
        }

        if ($this->_isSiteAdmin()) {
            $possibleColumns[] = 'creator_user';
        }

        $possibleColumns[] = 'timestamp';
        $possibleColumns[] = 'publish_timestamp';

        $userDisabledColumns = $this->User->UserSetting->getValueForUser($this->Auth->user()['id'], 'event_index_hide_columns');
        if ($userDisabledColumns === null) {
            $userDisabledColumns = self::DEFAULT_HIDDEN_INDEX_COLUMNS;
        }

        $enabledColumns = array_diff($possibleColumns, $userDisabledColumns);

        return [$possibleColumns, $enabledColumns];
    }

    private function __attachInfoToEvents(array $columns, array $events)
    {
        if (empty($events)) {
            return [];
        }

        $user = $this->Auth->user();

        if (in_array('tags', $columns, true) || in_array('clusters', $columns, true)) {
            $events = $this->Event->attachTagsToEvents($events);
            $events = $this->GalaxyCluster->attachClustersToEventIndex($user, $events, true);
            $events = $this->__attachHighlightedTagsToEvents($events);
        }

        if (in_array('correlations', $columns, true)) {
            $events = $this->Event->attachCorrelationCountToEvents($user, $events);
        }

        if (in_array('sightings', $columns, true)) {
            $events = $this->Event->attachSightingsCountToEvents($user, $events);
        }

        if (in_array('proposals', $columns, true)) {
            $events = $this->Event->attachProposalsCountToEvents($user, $events);
        }

        if (in_array('discussion', $columns, true) && !Configure::read('MISP.discussion_disable')) {
            $events = $this->Event->attachDiscussionsCountToEvents($user, $events);
        }

        if (in_array('report_count', $columns, true)) {
            $events = $this->Event->EventReport->attachReportCountsToEvents($user, $events);
        }

        return $events;
    }

    private function __noKeyNotification()
    {
        $onlyEncrypted = Configure::read('GnuPG.onlyencrypted');
        $bodyOnlyEncrypted = Configure::read('GnuPG.bodyonlyencrypted');
        if (!$onlyEncrypted && !$bodyOnlyEncrypted) {
            return;
        }

        $user = $this->Event->User->fillKeysToUser($this->Auth->user());
        if (!empty($user['gpgkey'])) {
            return; // use has PGP key
        }

        if ($onlyEncrypted) {
            if (Configure::read('SMIME.enabled') && empty($user['certif_public'])) {
                $this->Flash->info(__('No X.509 certificate or PGP key set in your profile. To receive emails, submit your public certificate or PGP key in your profile.'));
            } elseif (!Configure::read('SMIME.enabled')) {
                $this->Flash->info(__('No PGP key set in your profile. To receive emails, submit your public key in your profile.'));
            }
        } elseif ($bodyOnlyEncrypted && $user['autoalert']) {
            if (Configure::read('SMIME.enabled') && empty($user['certif_public'])) {
                $this->Flash->info(__('No X.509 certificate or PGP key set in your profile. To receive attributes in emails, submit your public certificate or PGP key in your profile.'));
            } elseif (!Configure::read('SMIME.enabled')) {
                $this->Flash->info(__('No PGP key set in your profile. To receive attributes in emails, submit your public key in your profile.'));
            }
        }
    }

    public function filterEventIndex()
    {
        $passedArgsArray = array();
        $filtering = array(
            'published' => 2,
            'org' => array('OR' => array(), 'NOT' => array()),
            'tag' => array('OR' => array(), 'NOT' => array()),
            'eventid' => array('OR' => array(), 'NOT' => array()),
            'date' => array('from' => "", 'until' => ""),
            'eventinfo' => array('OR' => array(), 'NOT' => array()),
            'all' => array('OR' => array(), 'NOT' => array()),
            'threatlevel' => array('OR' => array(), 'NOT' => array()),
            'distribution' => array('OR' => array(), 'NOT' => array()),
            'sharinggroup' => array('OR' => array(), 'NOT' => array()),
            'analysis' => array('OR' => array(), 'NOT' => array()),
            'attribute' => array('OR' => array(), 'NOT' => array()),
            'hasproposal' => 2,
            'timestamp' => array('from' => "", 'until' => ""),
            'publishtimestamp' => array('from' => "", 'until' => "")
        );

        if ($this->_isSiteAdmin()) {
            $filtering['email'] = array('OR' => array(), 'NOT' => array());
        }

        foreach ($this->passedArgs as $k => $v) {
            if (str_starts_with($k, 'search')) {
                $searchTerm = substr($k, 6);
                switch ($searchTerm) {
                    case 'published':
                    case 'hasproposal':
                        $filtering[$searchTerm] = $v;
                        break;
                    case 'Datefrom':
                        $filtering['date']['from'] = $v;
                        break;
                    case 'Dateuntil':
                        $filtering['date']['until'] = $v;
                        break;
                    case 'email':
                    case 'org':
                    case 'eventid':
                    case 'tag':
                    case 'eventinfo':
                    case 'attribute':
                    case 'threatlevel':
                    case 'distribution':
                    case 'sharinggroup':
                    case 'analysis':
                        if ($v == "" || ($searchTerm == 'email' && !$this->_isSiteAdmin())) {
                            continue 2;
                        }
                        $pieces = explode('|', $v);
                        foreach ($pieces as $piece) {
                            if ($piece[0] == '!') {
                                $filtering[$searchTerm]['NOT'][] = substr($piece, 1);
                            } else {
                                $filtering[$searchTerm]['OR'][] = $piece;
                            }
                        }
                        break;
                }
                $passedArgsArray[$searchTerm] = $v;
            }
        }
        $this->set('filtering', json_encode($filtering));

        $tagNames = $this->Event->EventTag->Tag->find('list', [
            'fields' => ['Tag.id', 'Tag.name'],
        ]);
        $tagJSON = [];
        foreach ($tagNames as $tagId => $tagName) {
            $tagJSON[] = array('id' => $tagId, 'value' => $tagName);
        }

        $rules = [
            'published' => __('Published'),
            'eventid' => __('Event ID'),
            'tag' => __('Tag'),
            'date' => __('Date'),
            'eventinfo' => __('Event info'),
            'threatlevel' => __('Threat level'),
            'distribution' => __('Distribution'),
            'sharinggroup' => __('Sharing group'),
            'analysis' => __('Analysis'),
            'attribute' => __('Attribute'),
            'hasproposal' => __('Has proposal'),
            'timestamp' => __('Last change at'),
            'publishtimestamp' => __('Published at'),
            'all' => __('Search in all fields'),
        ];

        if ($this->_isSiteAdmin()) {
            $rules['email'] = __('Email');
        }
        if (Configure::read('MISP.showorg')) {
            $orgs = $this->Event->Orgc->find('list', array(
                'fields' => array('Orgc.id', 'Orgc.name'),
                'sort' => array('lower(Orgc.name) asc')
            ));
            $this->set('showorg', true);
            $this->set('orgs', $orgs);
            $rules['org'] = __('Organisation');
        } else {
            $this->set('showorg', false);
        }
        $sharingGroups = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', true);
        $this->set('sharingGroups', $sharingGroups);
        $this->set('tags', $tagNames);
        $this->set('tagJSON', json_encode($tagJSON));
        $this->set('rules', $rules);
        $this->layout = false;
    }

    public function viewEventAttributes($id, $all = false)
    {
        $filterData = array(
            'paramArray' => self::ACCEPTED_FILTERING_NAMED_PARAMS,
            'named_params' => $this->request->params['named']
        );
        $filters = $this->_harvestParameters($filterData, $exception);
        if ($exception) {
            return $exception;
        }

        // Remove default filters
        foreach ($filters as $filterName => $filterValue) {
            if (isset(self::DEFAULT_FILTERING_RULE[$filterName]) && self::DEFAULT_FILTERING_RULE[$filterName] == $filterValue) {
                unset($filters[$filterName]);
            }
        }

        $this->Event->Attribute->includeAnalystData = true;
        $this->Event->Attribute->includeAnalystDataRecursive = true;

        if (isset($filters['focus'])) {
            $this->set('focus', $filters['focus']);
        }
        $conditions = [
            'eventid' => $id,
            'includeFeedCorrelations' => true,
            'includeWarninglistHits' => true,
            'fetchFullClusters' => false,
            'includeAllTags' => true,
            'includeGranularCorrelations' => true,
            'includeEventCorrelations' => true, // event correlations are need for filtering
            'noEventReports' => true, // event reports for view are loaded dynamically
            'noSightings' => true,
            'includeServerCorrelations' => $filters['includeServerCorrelations'] ?? 1,
        ];
        if (isset($filters['extended'])) {
            $conditions['extended'] = 1;
            $this->set('extended', 1);
        } else {
            $this->set('extended', 0);
        }
        if (!empty($filters['overrideLimit'])) {
            $conditions['overrideLimit'] = 1;
        }
        if (isset($filters['deleted'])) {
            if ($filters['deleted'] == 1) { // both
                $conditions['deleted'] = [0, 1];
            } elseif ($filters['deleted'] == 0) { // not-deleted only (default)
                $conditions['deleted'] = 0;
            } else { // only deleted
                $conditions['deleted'] = 1;
            }
        }
        if (isset($filters['toIDS']) && $filters['toIDS'] != 0) {
            $conditions['to_ids'] = $filters['toIDS'] == 2 ? 0 : 1;
        }
        if (!empty($filters['includeRelatedTags'])) {
            $this->set('includeRelatedTags', 1);
            $conditions['includeRelatedTags'] = 1;
        } else {
            $this->set('includeRelatedTags', 0);
        }
        if (!empty($filters['includeDecayScore'])) {
            $this->set('includeDecayScore', 1);
            $conditions['includeDecayScore'] = 1;
        } else {
            $this->set('includeDecayScore', 0);
        }

        // Site admin can view event as different user
        if ($this->_isSiteAdmin() && isset($this->request->params['named']['viewAs'])) {
            $user = $this->User->getAuthUser($this->request->params['named']['viewAs']);
            if (empty($user)) {
                throw new NotFoundException(__("User not found"));
            }
        } else {
            $user = $this->Auth->user();
        }

        $results = $this->Event->fetchEvent($user, $conditions);
        if (empty($results)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $event = $results[0];

        $emptyEvent = empty($event['Object']) && empty($event['Attribute']);
        $this->set('emptyEvent', $emptyEvent);

        $attributeTagsName = $this->Event->Attribute->AttributeTag->extractAttributeTagsNameFromEvent($event);
        $this->set('attributeTags', array_values($attributeTagsName['tags']));
        $this->set('attributeClusters', array_values($attributeTagsName['clusters']));

        if (isset($filters['distribution'])) {
            if (!is_array($filters['distribution'])) {
                $filters['distribution'] = array($filters['distribution']);
            }
            $temp = implode('|', $filters['distribution']);
            $this->__applyQueryString($event, $temp, 'distribution');
        }
        if (isset($filters['searchFor']) && $filters['searchFor'] !== '') {
            if (isset($filters['filterColumnsOverwrite'])) {
                $this->__applyQueryString($event, $filters['searchFor'], $filters['filterColumnsOverwrite']);
            } else {
                $this->__applyQueryString($event, $filters['searchFor']);
            }
            $this->set('passedArgsArray', array('all' => $filters['searchFor']));
        }
        if (isset($filters['taggedAttributes']) && $filters['taggedAttributes'] !== '') {
            $this->__applyQueryString($event, $filters['taggedAttributes'], 'Tag.name');
        }
        if (isset($filters['galaxyAttachedAttributes']) && $filters['galaxyAttachedAttributes'] !== '') {
            $this->__applyQueryString($event, $filters['galaxyAttachedAttributes'], 'Tag.name');
        }

        // remove galaxies tags
        $containsProposals = !empty($event['ShadowAttribute']);;
        $this->loadModel('Taxonomy');
        foreach ($event['Object'] as $k => $object) {
            if (isset($object['Attribute'])) {
                foreach ($object['Attribute'] as $k2 => $attribute) {
                    if (!empty($attribute['AttributeTag'])) {
                        $this->Event->Attribute->removeGalaxyClusterTags($event['Object'][$k]['Attribute'][$k2]);

                        $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
                        $event['Object'][$k]['Attribute'][$k2]['tagConflicts'] = $tagConflicts;
                    }
                    if (!$containsProposals && !empty($attribute['ShadowAttribute'])) {
                        $containsProposals = true;
                    }
                }
            }
        }

        foreach ($event['Attribute'] as &$attribute) {
            if (!empty($attribute['AttributeTag'])) {
                $this->Event->Attribute->removeGalaxyClusterTags($attribute);

                $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
                $attribute['tagConflicts'] = $tagConflicts;
            }
            if (!$containsProposals && !empty($attribute['ShadowAttribute'])) {
                $containsProposals = true;
            }
        }
        if (empty($this->passedArgs['sort'])) {
            $filters['sort'] = 'timestamp';
            $filters['direction'] = 'desc';
        }
        $sightingsData = $this->Event->Sighting->eventsStatistic([$event], $user);
        $this->set('sightingsData', $sightingsData);
        $params = $this->Event->rearrangeEventForView($event, $filters, $all, $sightingsData);
        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->loadModel('Sightingdb');
            $event = $this->Sightingdb->attachToEvent($event, $this->Auth->user());
        }
        $this->params->params['paging'] = array($this->modelClass => $params);
        $this->set('event', $event);
        $this->set('includeOrgColumn', (isset($conditions['extended']) || $containsProposals));
        $this->set('includeSightingdb', (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')));
        $this->set('deleted', isset($filters['deleted']) && $filters['deleted'] != 0);
        $this->set('attributeFilter', isset($filters['attributeFilter']) ? $filters['attributeFilter'] : 'all');
        $this->set('filters', $filters);
        $advancedFiltering = $this->__checkIfAdvancedFiltering($filters);
        $this->set('advancedFilteringActive', $advancedFiltering['active'] ? 1 : 0);
        $this->set('advancedFilteringActiveRules', $advancedFiltering['activeRules']);
        $this->set('mayModify', $this->__canModifyEvent($event, $user));
        $this->set('mayPublish', $this->__canPublishEvent($event, $user));
        $this->response->disableCache();

        // Remove `focus` attribute from URI
        $uriArray = explode('/', $this->request->here);
        foreach ($uriArray as $k => $v) {
            if (strpos($v, 'focus:') === 0) {
                unset($uriArray[$k]);
            }
            $this->request->here = implode('/', $uriArray);
        }

        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->set('sightingdbs', $this->Sightingdb->getSightingdbList($user));
        }
        $this->set('currentUri', $this->request->here);
        $this->layout = false;
        $this->__eventViewCommon($user);
        $this->render('/Elements/eventattribute');
    }

    /**
     * @param array $user
     * @param array $event
     * @param bool $continue
     * @param int $fromEvent
     */
    private function __viewUI(array $user, $event, $continue, $fromEvent)
    {
        $this->loadModel('Taxonomy');
        $filterData = array(
            'request' => $this->request,
            'paramArray' => self::ACCEPTED_FILTERING_NAMED_PARAMS,
            'named_params' => $this->request->params['named']
        );
        $exception = false;
        $warningTagConflicts = array();
        $filters = $this->_harvestParameters($filterData, $exception);
        $analystData = $this->Event->attachAnalystData($event['Event']);
        $event['Event'] = array_merge($event['Event'], $analystData);
        $emptyEvent = (empty($event['Object']) && empty($event['Attribute']));
        $this->set('emptyEvent', $emptyEvent);

        // set the data for the contributors / history field
        $contributors = $this->Event->ShadowAttribute->getEventContributors($event['Event']['id']);
        $this->set('contributors', $contributors);

        // set the pivot data
        $this->helpers[] = 'Pivot';
        if ($continue) {
            $this->__continuePivoting($event['Event']['id'], $event['Event']['info'], $event['Event']['date'], $fromEvent);
        } else {
            $this->__startPivoting($event['Event']['id'], $event['Event']['info'], $event['Event']['date']);
        }
        $pivot = $this->Session->read('pivot_thread');
        $this->__arrangePivotVertical($pivot);
        $this->__setDeletable($pivot, $event['Event']['id'], true);
        $this->set('allPivots', $this->Session->read('pivot_thread'));
        $this->set('pivot', $pivot);

        // workaround to get number of correlation per related event
        $relatedEventCorrelationCount = array();
        if (!empty($event['RelatedAttribute'])) {
            foreach ($event['RelatedAttribute'] as $relatedAttribute) {
                foreach ($relatedAttribute as $relation) {
                    $relatedEventCorrelationCount[$relation['id']][$relation['value']] = true;
                }
            }
        }
        foreach ($relatedEventCorrelationCount as $key => $relation) {
            $relatedEventCorrelationCount[$key] = count($relation);
        }

        $this->Event->removeGalaxyClusterTags($event);

        $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($event['EventTag']);
        foreach ($tagConflicts['global'] as $tagConflict) {
            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
        }
        foreach ($tagConflicts['local'] as $tagConflict) {
            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
        }
        $this->set('tagConflicts', $tagConflicts);

        $attributeCount = isset($event['Attribute']) ? count($event['Attribute']) : 0;
        $objectCount = isset($event['Object']) ? count($event['Object']) : 0;
        $oldestTimestamp = PHP_INT_MAX;
        $containsProposals = !empty($event['ShadowAttribute']);
        $modDate = date("Y-m-d", $event['Event']['timestamp']);
        $modificationMap = array($modDate => 1);
        foreach ($event['Attribute'] as $k => $attribute) {
            if ($oldestTimestamp > $attribute['timestamp']) {
                $oldestTimestamp = $attribute['timestamp'];
            }
            $modDate = date("Y-m-d", $attribute['timestamp']);
            $modificationMap[$modDate] = !isset($modificationMap[$modDate]) ? 1 : $modificationMap[$modDate] + 1;

            $this->Event->Attribute->removeGalaxyClusterTags($event['Attribute'][$k]);

            if (!empty($attribute['AttributeTag'])) {
                $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
                foreach ($tagConflicts['global'] as $tagConflict) {
                    $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                }
                foreach ($tagConflicts['local'] as $tagConflict) {
                    $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                }
                $event['Attribute'][$k]['tagConflicts'] = $tagConflicts;
            }
            if (!$containsProposals && !empty($attribute['ShadowAttribute'])) {
                $containsProposals = true;
            }
        }
        foreach ($event['Object'] as $k => $object) {
            $modDate = date("Y-m-d", $object['timestamp']);
            $modificationMap[$modDate] = !isset($modificationMap[$modDate])? 1 : $modificationMap[$modDate] + 1;
            if (!empty($object['Attribute'])) {
                $attributeCount += count($object['Attribute']);
                foreach ($object['Attribute'] as $k2 => $attribute) {
                    if ($oldestTimestamp > $attribute['timestamp']) {
                        $oldestTimestamp = $attribute['timestamp'];
                    }

                    $modDate = date("Y-m-d", $attribute['timestamp']);
                    $modificationMap[$modDate] = !isset($modificationMap[$modDate])? 1 : $modificationMap[$modDate] + 1;

                    $this->Event->Attribute->removeGalaxyClusterTags($event['Object'][$k]['Attribute'][$k2]);

                    if (!empty($attribute['AttributeTag'])) {
                        $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
                        foreach ($tagConflicts['global'] as $tagConflict) {
                            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                        }
                        foreach ($tagConflicts['local'] as $tagConflict) {
                            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                        }
                        $event['Object'][$k]['Attribute'][$k2]['tagConflicts'] = $tagConflicts;
                    }
                    if (!$containsProposals && !empty($attribute['ShadowAttribute'])) {
                        $containsProposals = true;
                    }
                }
            }
        }
        if ($containsProposals && $this->__canPublishEvent($event, $user)) {
            $mess = $this->Session->read('Message');
            if (empty($mess)) {
                $this->Flash->info(__('This event has active proposals for you to accept or discard.'));
            }
        }

        $attributeTagsName = $this->Event->Attribute->AttributeTag->extractAttributeTagsNameFromEvent($event);
        $this->set('attributeTags', array_values($attributeTagsName['tags']));
        $this->set('attributeClusters', array_values($attributeTagsName['clusters']));

        $this->set('warningTagConflicts', $warningTagConflicts);
        $filters['sort'] = 'timestamp';
        $filters['direction'] = 'desc';
        if (isset($filters['distribution'])) {
            if (!is_array($filters['distribution'])) {
                $filters['distribution'] = array($filters['distribution']);
            }
            $temp = implode('|', $filters['distribution']);
            $this->__applyQueryString($event, $temp, 'distribution');
        }
        $modificationMapCSV = 'Date,Close\n';
        $startDate = array_keys($modificationMap);
        sort($startDate);
        $startDate = $startDate[0];
        $this->set('startDate', $startDate);
        $today = strtotime(date('Y-m-d'));
        if (($today - 172800) > $startDate) {
            $startDate = date('Y-m-d', $today - 172800);
        }
        for ($date = $startDate; strtotime($date) <= $today; $date = date('Y-m-d', strtotime("+1 day", strtotime($date)))) {
            if (isset($modificationMap[$date])) {
                $modificationMapCSV .= $date . ',' . $modificationMap[$date] . '\n';
            } else {
                $modificationMapCSV .= $date . ',0\n';
            }
        }
        unset($modificationMap);
        $this->loadModel('Sighting');
        $sightingsData = $this->Sighting->eventsStatistic([$event], $user);
        $this->set('sightingsData', $sightingsData);
        $params = $this->Event->rearrangeEventForView($event, $filters, false, $sightingsData);
        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->loadModel('Sightingdb');
            $event = $this->Sightingdb->attachToEvent($event, $user);
        }
        $this->params->params['paging'] = array($this->modelClass => $params);
        $this->set('event', $event);
        $extensionParams = array(
            'conditions' => array(
                'Event.extends_uuid' => $event['Event']['uuid']
            )
        );
        $extensions = $this->Event->fetchSimpleEvents($user, $extensionParams);
        $this->set('extensions', $extensions);
        if (!empty($event['Event']['extends_uuid'])) {
            $extendedEvent = $this->Event->fetchSimpleEvents($user, array('conditions' => array('Event.uuid' => $event['Event']['extends_uuid'])));
            if (empty($extendedEvent)) {
                $extendedEvent = $event['Event']['extends_uuid'];
            }
            $this->set('extendedEvent', $extendedEvent);
        }
        if (Configure::read('MISP.delegation')) {
            $this->loadModel('EventDelegation');
            $delegationConditions = array('EventDelegation.event_id' => $event['Event']['id']);
            if (!$this->_isSiteAdmin() && $this->userRole['perm_publish']) {
                $delegationConditions['OR'] = array('EventDelegation.org_id' => $user['org_id'],
                                                    'EventDelegation.requester_org_id' => $user['org_id']);
            }
            $this->set('delegationRequest', $this->EventDelegation->find('first', array(
                'conditions' => $delegationConditions,
                'recursive' => -1,
                'contain' => array('Org', 'RequesterOrg')
            )));
        }

        $attributeUri = $this->baseurl . '/events/viewEventAttributes/' . $event['Event']['id'];
        foreach ($this->params->named as $k => $v) {
            if (!is_numeric($k)) {
                if (is_array($v)) {
                    foreach ($v as $value) {
                        $attributeUri .= sprintf('/%s[]:%s', $k, $value);
                    }
                } else {
                    $attributeUri .= sprintf('/%s:%s', $k, $v);
                }
            }
        }

        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->set('sightingdbs', $this->Sightingdb->getSightingdbList($user));
        }
        $this->set('includeOrgColumn', $this->viewVars['extended'] || $containsProposals);
        $this->set('includeSightingdb', !empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable'));
        $this->set('relatedEventCorrelationCount', $relatedEventCorrelationCount);
        $this->set('oldest_timestamp', $oldestTimestamp === PHP_INT_MAX ? false : $oldestTimestamp);
        $this->set('missingTaxonomies', $this->Event->missingTaxonomies($event));
        $this->set('currentUri', $attributeUri);
        $this->set('filters', $filters);
        $advancedFiltering = $this->__checkIfAdvancedFiltering($filters);
        $this->set('advancedFilteringActive', $advancedFiltering['active'] ? 1 : 0);
        $this->set('advancedFilteringActiveRules', $advancedFiltering['activeRules']);
        $this->set('modificationMapCSV', $modificationMapCSV);
        $this->set('title_for_layout', __('Event #%s', $event['Event']['id']));
        $this->set('attribute_count', $attributeCount);
        $this->set('object_count', $objectCount);
        $this->set('warnings', $this->Event->generateWarnings($event));
        $this->set('menuData', array('menuList' => 'event', 'menuItem' => 'viewEvent'));
        $this->set('mayModify', $this->__canModifyEvent($event, $user));
        $this->set('mayPublish', $this->__canPublishEvent($event, $user));
        try {
            $instanceKey = $event['Event']['protected'] ? $this->Event->CryptographicKey->ingestInstanceKey() : null;
        } catch (Exception $e) {
            $instanceKey = null;
        }
        $this->set('instanceFingerprint', $instanceKey);
        $this->__eventViewCommon($user);
    }

    private function __eventViewCommon(array $user)
    {
        $this->set('defaultFilteringRules', self::DEFAULT_FILTERING_RULE);
        $this->set('typeGroups', array_keys(MispAttribute::TYPE_GROUPINGS));

        $orgTable = $this->Event->Orgc->find('list', array(
            'fields' => array('Orgc.id', 'Orgc.name')
        ));
        $this->set('orgTable', $orgTable);

        $dataForView = array(
            'Attribute' => array('attrDescriptions' => 'fieldDescriptions', 'distributionDescriptions' => 'distributionDescriptions', 'distributionLevels' => 'distributionLevels', 'shortDist' => 'shortDist'),
            'Event' => array('eventDescriptions' => 'fieldDescriptions', 'analysisDescriptions' => 'analysisDescriptions', 'analysisLevels' => 'analysisLevels')
        );
        foreach ($dataForView as $m => $variables) {
            if ($m === 'Event') {
                $currentModel = $this->Event;
            } elseif ($m === 'Attribute') {
                $currentModel = $this->Event->Attribute;
            }
            foreach ($variables as $alias => $variable) {
                $this->set($alias, $currentModel->{$variable});
            }
        }

        if (Configure::read('Plugin.Enrichment_services_enable')) {
            $this->loadModel('Module');
            $modules = $this->Module->getEnabledModules($user);
            $this->set('modules', $modules);
        }
        if (Configure::read('Plugin.Cortex_services_enable')) {
            $this->loadModel('Module');
            $cortex_modules = $this->Module->getEnabledModules($user, false, 'Cortex');
            $this->set('cortex_modules', $cortex_modules);
        }
        $this->set('sightingsDbEnabled', (bool)Configure::read('Plugin.Sightings_sighting_db_enable'));
    }

    public function view($id = null, $continue = false, $fromEvent = null)
    {
        if ($this->request->is('head')) { // Just check if event exists
            $exists = $this->Event->fetchSimpleEvent($this->Auth->user(), $id, ['fields' => ['id']]);
            return new CakeResponse(['status' => $exists ? 200 : 404]);
        }

        if (is_numeric($id)) {
            $conditions = array('eventid' => $id);
        } else if (Validation::uuid($id)) {
            $conditions = array('event_uuid' => $id);
        } else {
            throw new NotFoundException(__('Invalid event'));
        }

        $namedParams = $this->request->params['named'];
        if ($this->_isRest()) {
            $conditions['includeAnalystData'] = true;
            $conditions['includeAttachments'] = isset($namedParams['includeAttachments']) ? $namedParams['includeAttachments'] : true;
        } else {
            $conditions['includeAllTags'] = true;
            $conditions['noEventReports'] = true; // event reports for view are loaded dynamically
            $conditions['noSightings'] = true;
            $conditions['fetchFullClusters'] = false;
        }
        $deleted = 0;
        if (isset($namedParams['deleted'])) {
            $deleted = $namedParams['deleted'];
        }
        if (isset($this->request->data['deleted'])) {
            $deleted = $this->request->data['deleted'];
        }
        // workaround for old instances trying to pull events with both deleted / non deleted data
        if (($this->userRole['perm_sync'] && $this->_isRest() && !$this->userRole['perm_site_admin']) && $deleted == 1) {
            $conditions['deleted'] = array(0, 1);
        } else {
            if (is_array($deleted)) {
                $conditions['deleted'] = $deleted;
            } else if ($deleted == 1) { // both
                $conditions['deleted'] = [0, 1];
            } elseif ($deleted == 0) { // not-deleted only
                $conditions['deleted'] = 0;
            } else { // only deleted
                $conditions['deleted'] = 1;
            }
        }
        if (isset($namedParams['toIDS']) && $namedParams['toIDS'] != 0) {
            $conditions['to_ids'] = $namedParams['toIDS'] == 2 ? 0 : 1;
        }
        if (isset($namedParams['includeRelatedTags']) && $namedParams['includeRelatedTags']) {
            $conditions['includeRelatedTags'] = 1;
        }
        if (!empty($namedParams['includeDecayScore'])) {
            $conditions['includeDecayScore'] = 1;
        }
        if (isset($namedParams['public']) && $namedParams['public']) {
            $conditions['distribution'] = array(3, 5);
        }
        if (!empty($namedParams['overrideLimit']) && !$this->_isRest()) {
            $conditions['overrideLimit'] = 1;
        }
        if (!empty($namedParams['excludeGalaxy'])) {
            $conditions['excludeGalaxy'] = 1;
            if (!empty($namedParams['includeCustomGalaxyCluster'])) {
                $conditions['includeCustomGalaxyCluster'] = 1;
            }
        }
        if (!empty($namedParams['extended']) || !empty($this->request->data['extended'])) {
            $conditions['extended'] = 1;
            $this->set('extended', 1);
        } else {
            $this->set('extended', 0);
        }
        $conditions['excludeLocalTags'] = false;
        $conditions['includeWarninglistHits'] = true;
        if (isset($namedParams['excludeLocalTags'])) {
            $conditions['excludeLocalTags'] = $namedParams['excludeLocalTags'];
        }
        $conditions['includeFeedCorrelations'] = 1;
        if (!$this->_isRest()) {
            $conditions['includeGranularCorrelations'] = 1;
        } else if (!empty($namedParams['includeGranularCorrelations'])) {
            $conditions['includeGranularCorrelations'] = 1;
        }
        if (!isset($namedParams['includeServerCorrelations'])) {
            $conditions['includeServerCorrelations'] = 1;
            if ($this->_isRest()) {
                $conditions['includeServerCorrelations'] = 0;
            }
        } else {
            $conditions['includeServerCorrelations'] = $namedParams['includeServerCorrelations'];
        }

        if ($this->_isRest()) {
            foreach (['includeEventCorrelations', 'includeFeedCorrelations', 'includeWarninglistHits', 'noEventReports', 'noShadowAttributes'] as $param) {
                if (isset($namedParams[$param])) {
                    $conditions[$param] = $namedParams[$param];
                }
            }
        }

        // Site admin can view event as different user
        if ($this->_isSiteAdmin() && isset($namedParams['viewAs'])) {
            $user = $this->User->getAuthUser($namedParams['viewAs']);
            if (empty($user)) {
                throw new NotFoundException(__("User not found"));
            }
            $this->Flash->info(__('Viewing event as %s from %s', h($user['email']), h($user['Organisation']['name'])));
        } else {
            $user = $this->Auth->user();
        }
        $results = $this->Event->fetchEvent($user, $conditions);
        if (empty($results)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $event = $results[0];
        // Attach related attributes to proper attribute
        if (!empty($namedParams['includeGranularCorrelations']) && !empty($event['RelatedAttribute'])) {
            foreach ($event['RelatedAttribute'] as $attribute_id => $relation) {
                foreach ($event['Attribute'] as $k2 => $attribute) {
                    if ((int)$attribute['id'] == $attribute_id) {
                        $event['Attribute'][$k2]['RelatedAttribute'][] = $relation;
                        break 2;
                    }
                }
                foreach ($event['Object'] as $k2 => $object) {
                    foreach ($object['Attribute'] as $k3 => $attribute) {
                        if ((int)$attribute['id'] == $attribute_id) {
                            $event['Object'][$k2]['Attribute'][$k3]['RelatedAttribute'][] = $relation;
                            break 3;
                        }
                    }
                }
            }
        }

        $this->Event->id = $event['Event']['id'];
        if (isset($namedParams['searchFor']) && $namedParams['searchFor'] !== '') {
            $this->__applyQueryString($event, $namedParams['searchFor']);
        }
        if (isset($namedParams['taggedAttributes']) && $namedParams['taggedAttributes'] !== '') {
            $this->__applyQueryString($event, $namedParams['taggedAttributes'], 'Tag.name');
        }
        if (isset($namedParams['galaxyAttachedAttributes']) && $namedParams['galaxyAttachedAttributes'] !== '') {
            $this->__applyQueryString($event, $namedParams['galaxyAttachedAttributes'], 'Tag.name');
        }
        if ($this->_isRest()) {
            if ($this->RestResponse->isAutomaticTool() && $event['Event']['protected']) {
                $this->RestResponse->signContents = true;
            }
            return $this->__restResponse($event);
        }

        $this->set('deleted', $deleted > 0);
        $this->set('includeRelatedTags', (!empty($namedParams['includeRelatedTags'])) ? 1 : 0);
        $this->set('includeDecayScore', (!empty($namedParams['includeDecayScore'])) ? 1 : 0);

        $this->__setHighlightedTags($event);

        if ($this->_isSiteAdmin() && $event['Event']['orgc_id'] !== $this->Auth->user('org_id')) {
            $this->Flash->info(__('You are currently logged in as a site administrator and about to edit an event not belonging to your organisation. This goes against the sharing model of MISP. Use a normal user account for day to day work.'));
        }
        $this->__viewUI($user, $event, $continue, $fromEvent);
    }

    /**
     * @param int $id
     * @param string $info
     * @param string $date
     */
    private function __startPivoting($id, $info, $date)
    {
        $initialPivot = [
            'id' => $id,
            'info' => $info,
            'date' => $date,
            'depth' => 0,
            'height' => 0,
            'children' => [],
            'deletable' => true,
        ];
        $this->Session->write('pivot_thread', $initialPivot);
    }

    /**
     * @param int $id
     * @param string $info
     * @param string $date
     * @param int $fromEvent
     */
    private function __continuePivoting($id, $info, $date, $fromEvent)
    {
        $pivot = $this->Session->read('pivot_thread');
        if (!is_array($pivot)) {
            $this->__startPivoting($id, $info, $date);
            return;
        }

        $newPivot = [
            'id' => $id,
            'info' => $info,
            'date' => $date,
            'depth' => null,
            'children' => [],
            'deletable' => true,
        ];
        if (!$this->__checkForPivot($pivot, $id)) {
            $pivot = $this->__insertPivot($pivot, $fromEvent, $newPivot, 0);
        }
        $this->Session->write('pivot_thread', $pivot);
    }

    /**
     * @param array $pivot
     * @param int $oldId
     * @param array $newPivot
     * @param int $depth
     * @return array
     */
    private function __insertPivot(array $pivot, $oldId, array $newPivot, $depth)
    {
        $depth++;
        if ($pivot['id'] == $oldId) {
            $newPivot['depth'] = $depth;
            $pivot['children'][] = $newPivot;
            return $pivot;
        }
        if (!empty($pivot['children'])) {
            foreach ($pivot['children'] as $k => $v) {
                $pivot['children'][$k] = $this->__insertPivot($v, $oldId, $newPivot, $depth);
            }
        }
        return $pivot;
    }

    /**
     * @param array $pivot
     * @param int $id
     * @return bool
     */
    private function __checkForPivot(array $pivot, $id)
    {
        if ($id == $pivot['id']) {
            return true;
        }
        foreach ($pivot['children'] as $k => $v) {
            if ($this->__checkForPivot($v, $id)) {
                return true;
            }
        }
        return false;
    }

    private function __arrangePivotVertical(&$pivot)
    {
        if (empty($pivot)) {
            return null;
        }
        $max = count($pivot['children']) - 1;
        if ($max < 0) {
            $max = 0;
        }
        $temp = 0;
        $pivot['children'] = array_values($pivot['children']);
        foreach ($pivot['children'] as $k => $v) {
            $pivot['children'][$k]['height'] = ($temp+$k)*50;
            $temp += $this->__arrangePivotVertical($pivot['children'][$k]);
            if ($k == $max) {
                $temp = $pivot['children'][$k]['height'] / 50;
            }
        }
        return $temp;
    }

    public function removePivot($id, $eventId, $self = false)
    {
        $pivot = $this->Session->read('pivot_thread');
        if ($pivot['id'] == $id) {
            $pivot = null;
            $this->Session->write('pivot_thread', null);
            $this->redirect(array('controller' => 'events', 'action' => 'view', $eventId));
        } else {
            $pivot = $this->__doRemove($pivot, $id);
        }
        $this->Session->write('pivot_thread', $pivot);
        $pivot = $this->__arrangePivotVertical($pivot);
        $this->redirect(array('controller' => 'events', 'action' => 'view', $eventId, true, $eventId));
    }

    /**
     * @param array $event
     * @param string $searchFor
     * @param string|false $filterColumnsOverwrite
     */
    private function __applyQueryString(&$event, $searchFor, $filterColumnsOverwrite = false)
    {
        // filtering on specific columns is specified
        if ($filterColumnsOverwrite !== false) {
            $filterValue = array_map('trim', explode(",", $filterColumnsOverwrite));
        } else {
            $filterColumnsOverwrite = Configure::read('MISP.event_view_filter_fields') ?: 'id,uuid,value,comment,type,category,Tag.name';
            $filterValue = array_map('trim', explode(",", $filterColumnsOverwrite));
            $validFilters = ['id', 'uuid', 'value', 'comment', 'type', 'category', 'Tag.name'];
            foreach ($filterValue as $k => $v) {
                if (!in_array($v, $validFilters, true)) {
                    unset($filterValue[$k]);
                }
            }
        }

        $searchParts = explode('|', mb_strtolower($searchFor));

        // search in all attributes
        $foundAttributes = [];
        foreach ($event['Attribute'] as $attribute) {
            if ($this->__valueInFieldAttribute($attribute, $filterValue, $searchParts)) {
                $foundAttributes[] = $attribute;
            }
        }
        $event['Attribute'] = $foundAttributes;

        // search in all proposals
        $foundProposals = [];
        foreach ($event['ShadowAttribute'] as $proposals) {
            if ($this->__valueInFieldAttribute($proposals, $filterValue, $searchParts)) {
                $foundProposals[] = $proposals;
            }
        }
        $event['ShadowAttribute'] = $foundProposals;

        // search for all attributes in object
        foreach ($event['Object'] as $k => $object) {
            if ($this->__valueInFieldAttribute($object, ['id', 'uuid', 'name', 'comment'], $searchParts)) {
                continue;
            }
            $foundAttributes = [];
            foreach ($object['Attribute'] as $attribute) {
                if ($this->__valueInFieldAttribute($attribute, $filterValue, $searchParts)) {
                    $foundAttributes[] = $attribute;
                }
            }
            if (empty($foundAttributes)) {
                unset($event['Object'][$k]); // remove object if contains no attributes
            } else {
                $event['Object'][$k]['Attribute'] = $foundAttributes;
            }
        }
        $event['Object'] = array_values($event['Object']);
    }

    /**
     * Search for a value on an attribute level for a specific field.
     *
     * @param array $attribute An attribute
     * @param array $fields List of keys in attribute to search in
     * @param array $searchParts Values to search (OR)
     * @return bool Returns true on match
     */
    private function __valueInFieldAttribute($attribute, $fields, $searchParts)
    {
        foreach ($fields as $field) {
            if ($field === 'Tag.name') {
                if (empty($attribute['AttributeTag'])) {
                    continue;
                }
                foreach ($attribute['AttributeTag'] as $fieldValue) {
                    $fieldValue = mb_strtolower($fieldValue['Tag']['name']);
                    foreach ($searchParts as $s) {
                        if (strpos($fieldValue, $s) !== false) {
                            return true;
                        }
                    }
                }
            } else {
                if (!isset($attribute[$field])) {
                    continue;
                }
                $fieldValue = mb_strtolower($attribute[$field]);
                foreach ($searchParts as $s) {
                    if (strpos($fieldValue, $s) !== false) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // look in the parameters if we are doing advanced filtering or not
    private function __checkIfAdvancedFiltering($filters)
    {
        $advancedFilteringActive = array_diff_key($filters, array('sort'=>0, 'direction'=>0, 'focus'=>0, 'overrideLimit'=>0, 'filterColumnsOverwrite'=>0, 'attributeFilter'=>0, 'extended' => 0, 'page' => 0));

        if (count($advancedFilteringActive) > 0) {
            if (count(array_diff_key($advancedFilteringActive, array('deleted', 'includeRelatedTags', 'includeDecayScore'))) > 0) {
                $res =  true;
            } else if (
                (isset($advancedFilteringActive['deleted']) && $advancedFilteringActive['deleted'] == 2) ||
                (isset($advancedFilteringActive['includeRelatedTags']) && $advancedFilteringActive['includeRelatedTags'] == 1) ||
                (isset($advancedFilteringActive['includeDecayScore']) && $advancedFilteringActive['includeDecayScore'] == 1)
            ) {
                $res =  true;
            } else {
                $res =  false;
            }
        } else {
            $res = false;
        }

        unset($filters['sort']);
        unset($filters['direction']);
        $activeRules = array();
        foreach ($filters as $k => $v) {
            if (isset(self::DEFAULT_FILTERING_RULE[$k]) && self::DEFAULT_FILTERING_RULE[$k] != $v) {
                $activeRules[$k] = $v;
            }
        }
        return array('active' => $activeRules > 0 ? $res : false, 'activeRules' => $activeRules);
    }

    private function __doRemove(&$pivot, $id)
    {
        foreach ($pivot['children'] as $k => $v) {
            if ($v['id'] == $id) {
                unset($pivot['children'][$k]);
                return $pivot;
            } else {
                $pivot['children'][$k] = $this->__doRemove($pivot['children'][$k], $id);
            }
        }
        return $pivot;
    }

    private function __setDeletable(&$pivot, $id, $root=false)
    {
        if ($pivot['id'] == $id && !$root) {
            $pivot['deletable'] = false;
            return true;
        }
        if (!empty($pivot['children'])) {
            foreach ($pivot['children'] as $k => $v) {
                $containsCurrent = $this->__setDeletable($pivot['children'][$k], $id);
                if ($containsCurrent && !$root) {
                    $pivot['deletable'] = false;
                }
            }
        }
        return !$pivot['deletable'];
    }

    public function add()
    {
        $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        if ($this->request->is('post')) {
            if ($this->_isRest()) {
                if (empty($this->data)) {
                    throw new MethodNotAllowedException(__('No valid event data received.'));
                }
                // rearrange the response if the event came from an export
                if (isset($this->request->data['response'])) {
                    $this->request->data = $this->request->data['response'];
                }
                if (isset($this->request->data['request'])) {
                    $this->request->data = $this->request->data['request'];
                }
                if (!isset($this->request->data['Event'])) {
                    $this->request->data = array('Event' => $this->request->data);
                }

                // Distribution, reporter for the events pushed will be the owner of the authentication key
                $this->request->data['Event']['user_id'] = $this->Auth->user('id');
            }
            if (
                !empty($this->request->data['Event']['protected']) &&
                $this->Auth->user('Role')['perm_sync'] &&
                !$this->Auth->user('Role')['perm_site_admin']
            ) {
                $pgp_signature = $this->request->header('x-pgp-signature');
                if (empty($pgp_signature)) {
                    throw new MethodNotAllowedException(__('Protected event failed signature validation as no key was provided.'));
                }
                $raw_data = $this->request->input();
                if (
                    !$this->Event->CryptographicKey->validateProtectedEvent(
                        $raw_data,
                        $this->Auth->user(),
                        $pgp_signature,
                        $this->request->data
                    )
                ) {
                    throw new MethodNotAllowedException(__('Protected event failed signature validation.'));
                }
            }
            if (!empty($this->data)) {
                if (!isset($this->request->data['Event']['distribution'])) {
                    $this->request->data['Event']['distribution'] = Configure::read('MISP.default_event_distribution') ?: 0;
                }
                if (!isset($this->request->data['Event']['analysis'])) {
                    $this->request->data['Event']['analysis'] = 0;
                }
                if (!isset($this->request->data['Event']['threat_level_id'])) {
                    $this->request->data['Event']['threat_level_id'] = Configure::read('MISP.default_event_threat_level') ?: 4;
                }
                if (!isset($this->request->data['Event']['date'])) {
                    $this->request->data['Event']['date'] = date('Y-m-d');
                }
                // If the distribution is set to sharing group, check if the id provided is really visible to the user, if not throw an error.
                if ($this->request->data['Event']['distribution'] == 4) {
                    if ($this->userRole['perm_sync'] && $this->_isRest()) {
                        if (isset($this->request->data['Event']['SharingGroup'])) {
                            if (!isset($this->request->data['Event']['SharingGroup']['uuid'])) {
                                if ($this->Event->SharingGroup->checkIfExists($this->request->data['Event']['SharingGroup']['uuid']) &&
                                    $this->Event->SharingGroup->checkIfAuthorised($this->Auth->user(), $this->request->data['Event']['SharingGroup']['uuid'])) {
                                    throw new MethodNotAllowedException(__('Invalid Sharing Group or not authorised (Sync user is not contained in the Sharing group).'));
                                }
                            }
                        } elseif (!isset($sgs[$this->request->data['Event']['sharing_group_id']])) {
                            throw new MethodNotAllowedException(__('Invalid Sharing Group or not authorised.'));
                        }
                    } else {
                        if (!isset($sgs[$this->request->data['Event']['sharing_group_id']])) {
                            throw new MethodNotAllowedException(__('Invalid Sharing Group or not authorised.'));
                        }
                    }
                } else {
                    // If the distribution is set to something "traditional", set the SG id to 0.
                    $this->request->data['Event']['sharing_group_id'] = 0;
                }
                // If we are not sync users / site admins, we only allow events to be created for our own org
                // Set the orgc ID as our own orgc ID and unset both the 2.4 and 2.3 style creator orgs
                if ($this->_isRest() && !$this->userRole['perm_sync']) {
                    $this->request->data['Event']['orgc_id'] = $this->Auth->user('org_id');
                    if (isset($this->request->data['Event']['Orgc'])) {
                        unset($this->request->data['Event']['Orgc']);
                    }
                    if (isset($this->request->data['Event']['orgc'])) {
                        unset($this->request->data['Event']['orgc']);
                    }
                }
                $validationErrors = array();
                $created_id = 0;
                $add = $this->Event->_add($this->request->data, $this->_isRest(), $this->Auth->user(), '', null, false, null, $created_id, $validationErrors);
                if ($add === true) {
                    if ($this->_isRest()) {
                        // REST users want to see the newly created event
                        $metadata = $this->request->param('named.metadata');
                        $results = $this->Event->fetchEvent($this->Auth->user(), ['eventid' => $created_id, 'metadata' => $metadata]);
                        $event = $results[0];
                        if (!empty($validationErrors)) {
                            $event['errors'] = $validationErrors;
                        }
                        return $this->__restResponse($event);
                    } else {
                        // redirect to the view of the newly created event
                        $this->Flash->success(__('The event has been saved'));
                        $this->redirect(array('action' => 'view', $this->Event->getID()));
                    }
                } else {
                    if ($this->_isRest()) { // TODO return error if REST
                        if (is_numeric($add)) {
                            $this->response->header('Location', $this->baseurl . '/events/' . $add);
                            $this->response->send();
                            throw new NotFoundException(__('Event already exists, if you would like to edit it, use the url in the location header.'));
                        }

                        if ($add === 'blocked') {
                            throw new ForbiddenException(__('Event blocked by organisation blocklist.'));
                        } else if ($add === 'Blocked by blocklist') {
                            throw new ForbiddenException(__('Event blocked by event blocklist.'));
                        } else if ($add === 'Blocked by event block rules') {
                            throw new ForbiddenException(__('Blocked by event block rules.'));
                        }

                        // # TODO i18n?
                        return $this->RestResponse->saveFailResponse('Events', 'add', false, $validationErrors, $this->response->type());
                    } else {
                        if ($add === 'blocked') {
                            $this->Flash->error(__('A blocklist entry is blocking you from creating any events. Please contact the administration team of this instance') . (Configure::read('MISP.contact') ? ' at ' . Configure::read('MISP.contact') : '') . '.');
                        } else {
                            $this->Flash->error(__('The event could not be saved. Please, try again.'), 'default', array(), 'error');
                        }
                    }
                }
            }
        } elseif ($this->_isRest()) {
            return $this->RestResponse->describe('Events', 'add', false, $this->response->type());
        }

        $this->request->data['Event']['date'] = date('Y-m-d');
        if (isset($this->request->data['Event']['distribution'])) {
            $initialDistribution = $this->request->data['Event']['distribution'];
        } else {
            $initialDistribution = 3;
            if (Configure::read('MISP.default_event_distribution') != null) {
                $initialDistribution = Configure::read('MISP.default_event_distribution');
            }
        }
        $this->set('initialDistribution', $initialDistribution);

        // combobox for distribution
        $distributions = array_keys($this->Event->distributionDescriptions);
        $distributions = $this->_arrayToValuesIndexArray($distributions);
        $this->set('distributions', $distributions);
        // tooltip for distribution
        $fieldDesc = array();
        $distributionLevels = $this->Event->distributionLevels;
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        $this->set('distributionLevels', $distributionLevels);
        foreach ($distributionLevels as $key => $value) {
            $fieldDesc['distribution'][$key] = $this->Event->distributionDescriptions[$key]['formdesc'];
        }

        // combobox for risks
        $threat_levels = array_column($this->Event->ThreatLevel->find('all'), 'ThreatLevel');
        $this->set('threatLevels', array_column($threat_levels, 'name', 'id'));
        $fieldDesc['threat_level_id'] = array_column($threat_levels, 'description', 'id');

        // combobox for analysis
        $this->set('sharingGroups', $sgs);
        // tooltip for analysis
        $analysisLevels = $this->Event->analysisLevels;
        $this->set('analysisLevels', $analysisLevels);
        foreach ($analysisLevels as $key => $value) {
            $fieldDesc['analysis'][$key] = $this->Event->analysisDescriptions[$key]['formdesc'];
        }

        if (Configure::read('MISP.unpublishedprivate')) {
            $this->Flash->info(__('The event created will be visible only to your organisation until it is published.'));
        } else {
            $this->Flash->info(__('The event created will be visible to the organisations having an account on this platform, but not synchronised to other MISP instances until it is published.'));
        }
        $this->set('fieldDesc', $fieldDesc);
        if (isset($this->params['named']['extends'])) {
            $this->set('extends_uuid', $this->params['named']['extends']);
        }
    }

    public function addIOC($id)
    {
        $this->Event->recursive = -1;
        $this->Event->read(null, $id);
        if (!$this->__canModifyEvent($this->Event->data)) {
            throw new UnauthorizedException(__('You do not have permission to do that.'));
        }
        if ($this->request->is('post')) {
            if (!empty($this->data)) {
                if (isset($this->data['Event']['submittedioc'])) {
                    $this->_addIOCFile($id);
                }

                // redirect to the view of the newly created event
                $this->Flash->success(__('The event has been saved'));
            }
        }
        // set the id
        $this->set('id', $id);
        // set whether it is published or not
        $this->set('published', $this->Event->data['Event']['published'] ?? false);
    }

    public function add_misp_export()
    {
        if ($this->request->is('post')) {
            $results = array();
            if (!empty($this->request->data)) {
                if (empty($this->request->data['Event'])) {
                    $this->request->data['Event'] = $this->request->data;
                }
                if (!empty($this->request->data['Event']['filecontent'])) {
                    $data = $this->request->data['Event']['filecontent'];
                    $isXml = $data[0] === '<';
                } elseif (isset($this->request->data['Event']['submittedfile'])) {
                    $file = $this->request->data['Event']['submittedfile'];
                    if ($file['error'] === UPLOAD_ERR_NO_FILE) {
                        $this->Flash->error(__('No file was uploaded.'));
                        $this->redirect(['controller' => 'events', 'action' => 'add_misp_export']);
                    }

                    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                    if (($ext !== 'xml' && $ext !== 'json') && $file['size'] > 0 && is_uploaded_file($file['tmp_name'])) {
                        $log = ClassRegistry::init('Log');
                        $log->createLogEntry($this->Auth->user(), 'file_upload', 'Event', 0, 'MISP export file upload failed', 'File details: ' . json_encode($file));
                        $this->Flash->error(__('You may only upload MISP XML or MISP JSON files.'));
                        throw new MethodNotAllowedException(__('File upload failed or file does not have the expected extension (.xml / .json).'));
                    }

                    $isXml = $ext === 'xml';
                    $matches = null;
                    $tmp_name = $file['tmp_name'];
                    if (preg_match_all('/[\w\/\-\.]*/', $tmp_name, $matches) && file_exists($file['tmp_name'])) {
                        $data = FileAccessTool::readFromFile($matches[0][0], $file['size']);
                    } else {
                        throw new NotFoundException(__('Invalid file.'));
                    }
                } else {
                    throw new MethodNotAllowedException(__('No file uploaded.'));
                }

                $takeOwnership = Configure::read('MISP.take_ownership_xml_import')
                    && (isset($this->request->data['Event']['takeownership']) && $this->request->data['Event']['takeownership'] == 1);

                $publish = $this->request->data['Event']['publish'] ?? false;
                try {
                    $results = $this->Event->addMISPExportFile($this->Auth->user(), $data, $isXml, $takeOwnership, $publish);
                } catch (Exception $e) {
                    $this->log("Exception during processing MISP file import: {$e->getMessage()}");
                    $this->Flash->error(__('Could not process MISP export file. %s', $e->getMessage()));
                    $this->redirect(['controller' => 'events', 'action' => 'add_misp_export']);
                }
            }
            $this->set('results', $results);
            $this->render('add_misp_export_result');
        }
        $this->set('title_for_layout', __('Import from MISP Export File'));
    }

    public function upload_stix($stix_version = '1', $publish = false, $galaxies_as_tags = true, $debug = false)
    {
        $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $initialDistribution = 0;
        if (Configure::read('MISP.default_event_distribution') != null) {
            $initialDistribution = Configure::read('MISP.default_event_distribution');
        }
        $distributionLevels = $this->Event->distributionLevels;
        if ($this->request->is('post')) {
            if ($this->_isRest()) {
                if (isset($this->params['named']['publish'])) {
                    $publish = $this->params['named']['publish'];
                }
                if (isset($this->params['named']['distribution'])) {
                    $distribution = intval($this->params['named']['distribution']);
                    if (!array_key_exists($distribution, $distributionLevels)) {
                        throw new BadRequestException(__('Wrong distribution level'));
                    }
                } else {
                    $distribution = $initialDistribution;
                }
                $sharingGroupId = null;
                if ($distribution == 4) {
                    if (!isset($this->params['named']['sharing_group_id'])) {
                        throw new BadRequestException(__('The sharing group id is needed when the distribution is set to 4 ("Sharing group").'));
                    }
                    $sharingGroupId = intval($this->params['named']['sharing_group_id']);
                    if (!array_key_exists($sharingGroupId, $sgs)) {
                        throw new BadRequestException(__('Please select a valid sharing group id.'));
                    }
                }
                $clusterDistribution = $initialDistribution;
                $clusterSharingGroupId = null;
                if (isset($this->params['named']['galaxies_as_tags'])) {
                    $galaxies_as_tags = $this->params['named']['galaxies_as_tags'];
                    if (isset($this->params['name']['cluster_distribution'])) {
                        $clusterDistribution = intval($this->params['named']['cluster_distribution']);
                        if (!array_key_exists($clusterDistribution, $distributionLevels)) {
                            throw new BadRequestException(__('Wrong cluster distribution level'));
                        }
                        if ($clusterDistribution == 4) {
                            if (!isset($this->params['named']['cluster_sharing_group_id'])) {
                                throw new BadRequestException(__('The cluster sharing group id is needed when the cluster distribution is set to 4 ("Sharing group").'));
                            }
                            $clusterSharingGroupId = intval($this->params['named']['cluster_sharing_group_id']);
                            if (!array_key_exists($clusterSharingGroupId, $sgs)) {
                                throw new BadRequestException(__('Please select a valid cluster sharing group id.'));
                            }
                        }
                    }
                }
                if (isset($this->params['named']['debugging'])) {
                    $debug = $this->params['named']['debugging'];
                }
                $filePath = FileAccessTool::writeToTempFile($this->request->input());
                $result = $this->Event->upload_stix(
                    $this->Auth->user(),
                    $filePath,
                    $stix_version,
                    'uploaded_stix_file.' . ($stix_version == '1' ? 'xml' : 'json'),
                    $publish,
                    $distribution,
                    $sharingGroupId,
                    $galaxies_as_tags,
                    $clusterDistribution,
                    $clusterSharingGroupId,
                    $debug
                );
                if (is_numeric($result)) {
                    $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $result));
                    if (!empty($event)) {
                        return $this->RestResponse->viewData($event[0], 'json');
                    } else {
                        return $this->RestResponse->saveFailResponse('Events', 'upload_stix', false, 'Could not read saved event.', $this->response->type());
                    }
                } else {
                    return $this->RestResponse->saveFailResponse('Events', 'upload_stix', false, $result, $this->response->type());
                }
            } else { // not REST request
                $originalFile = !empty($this->data['Event']['original_file']) ? $this->data['Event']['stix']['name'] : '';
                if (isset($this->data['Event']['stix']) && $this->data['Event']['stix']['size'] > 0 && is_uploaded_file($this->data['Event']['stix']['tmp_name'])) {
                    $filePath = FileAccessTool::createTempFile();
                    if (!move_uploaded_file($this->data['Event']['stix']['tmp_name'], $filePath)) {
                        throw new Exception("Could not move uploaded STIX file.");
                    }
                    if (isset($this->data['Event']['debug'])) {
                        $debug = $this->data['Event']['debug'];
                    }
                    $result = $this->Event->upload_stix(
                        $this->Auth->user(),
                        $filePath,
                        $stix_version,
                        $originalFile,
                        $this->data['Event']['publish'],
                        $this->data['Event']['distribution'],
                        $this->data['Event']['sharing_group_id'] ?? null,
                        $this->data['Event']['galaxies_handling'] ?? false,
                        $this->data['Event']['cluster_distribution'] ?? 0,
                        $this->data['Event']['cluster_sharing_group_id'] ?? null,
                        $debug
                    );
                    if (is_numeric($result)) {
                        $this->Flash->success(__('STIX document imported.'));
                        $this->redirect(array('action' => 'view', $result));
                    } else {
                        $this->Flash->error(__('Could not import STIX document: %s', $result));
                    }
                } else {
                    $maxUploadSize = intval(ini_get('post_max_size'));
                    if (intval(ini_get('upload_max_filesize')) < $maxUploadSize) {
                        $maxUploadSize = intval(ini_get('upload_max_filesize'));
                    }
                    $this->Flash->error(__('File upload failed. Make sure that you select a STIX file to be uploaded and that the file doesn\'t exceed the maximum file size of %s MB.', $maxUploadSize));
                }
            }
        }
        $this->set('stix_version', $stix_version == 2 ? '2.x JSON' : '1.x XML');
        $this->set('initialDistribution', $initialDistribution);
        $distributions = array_keys($this->Event->distributionDescriptions);
        $distributions = $this->_arrayToValuesIndexArray($distributions);
        $this->set('distributions', $distributions);
        $fieldDesc = array();
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        $this->set('distributionLevels', $distributionLevels);
        foreach ($distributionLevels as $key => $value) {
            $fieldDesc['distribution'][$key] = $this->Event->distributionDescriptions[$key]['formdesc'];
        }

        $debugOptions = [
            0 => __('Standard debugging'),
            1 => __('Advanced debugging'),
        ];
        $debugDescriptions = [
            0 => __('The critical errors are logged in the usual log file.'),
            1 => __('All the errors and warnings are logged in the usual log file.'),
        ];
        $galaxiesOptions = [
            0 => __('As MISP standard format'),
            1 => __('As tag names'),
        ];
        $galaxiesOptionsDescriptions = [
            0 => __('Galaxies and Clusters are passed as MISP standard format. New generic Galaxies and Clusters are created when there is no match with existing ones.'),
            1 => __('Galaxies are passed as tags and there is only a simple search with existing galaxy tag names.'),
        ];

        $this->set('debugOptions', $debugOptions);
        foreach ($debugOptions as $key => $value) {
            $fieldDesc['debug'][$key] = $debugDescriptions[$key];
        }
        $this->set('galaxiesOptions', $galaxiesOptions);
        foreach ($galaxiesOptions as $key => $value) {
            $fieldDesc['galaxies_handling'][$key] = $galaxiesOptionsDescriptions[$key];
        }
        $this->set('sharingGroups', $sgs);
        $this->set('fieldDesc', $fieldDesc);
    }

    public function merge($target_id=null, $source_id=null)
    {
        if ($this->request->is('post')) {
            if (empty($this->request->data['Event'])) {
                $this->request->data = ['Event' => $this->request->data];
            }
        }
        $extractedParams = array('target_id', 'source_id');
        foreach ($extractedParams as $param) {
            if (empty(${$param})) {
                if (!empty($this->request->data['Event'][$param])) {
                    ${$param} = $this->request->data['Event'][$param];
                } else {
                    if ($param === 'target_id' || $this->request->is('post')) {
                        throw new InvalidArgumentException(__('This action requires a target_id for GET requests and both a target_id and a source_id for POST requests.'));
                    }
                }
            }
        }
        $target_event = $this->Event->fetchSimpleEvent($this->Auth->user(), $target_id, ['contain' => ['Orgc']]);
        if (empty($target_event)) {
            throw new NotFoundException(__('Invalid target event.'));
        }
       if (!$this->__canModifyEvent($target_event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        if ($this->request->is('post')) {
            $source_id = $this->Toolbox->findIdByUuid($this->Event, $source_id);
            $source_event = $this->Event->fetchEvent(
                $this->Auth->user(),
                [
                    'eventid' => $source_id,
                    'includeAllTags' => 1,
                    'includeAttachments' => 1
                ]
            );
            if (empty($source_event)) {
                throw new NotFoundException(__('Invalid source event.'));
            }
            $recovered_uuids = [];
            foreach ($source_event[0]['Attribute'] as &$attribute) {
                unset($attribute['id']);
                $originalUUID = $attribute['uuid'];
                $attribute['uuid'] = CakeText::uuid();
                $recovered_uuids[$originalUUID] = $attribute['uuid'];
                unset($attribute['ShadowAttribute']);
                $attribute['Tag'] = [];
                foreach ($attribute['AttributeTag'] as $aT) {
                    $attribute['Tag'][] = $aT['Tag'];
                    $aT['Tag']['local'] = $aT['local'];
                }
                unset($attribute['AttributeTag']);
            }
            foreach ($source_event[0]['Object'] as &$object) {
                unset($object['id']);
                $originalUUID = $object['uuid'];
                $object['uuid'] = CakeText::uuid();
                $recovered_uuids[$originalUUID] = $object['uuid'];
                foreach ($object['Attribute'] as &$attribute) {
                    unset($attribute['id']);
                    $originalUUID = $attribute['uuid'];
                    $attribute['uuid'] = CakeText::uuid();
                    $recovered_uuids[$originalUUID] = $attribute['uuid'];
                    unset($attribute['ShadowAttribute']);
                    $attribute['Tag'] = [];
                    foreach ($attribute['AttributeTag'] as $aT) {
                        $attribute['Tag'][] = $aT['Tag'];
                        $aT['Tag']['local'] = $aT['local'];
                    }
                    unset($attribute['AttributeTag']);
                }
            }
            foreach ($source_event[0]['Object'] as &$object) {
                foreach ($object['ObjectReference'] as &$reference) {
                    if (isset($recovered_uuids[$object['uuid']])) {
                        $reference['object_uuid'] = $recovered_uuids[$object['uuid']];
                    }
                    if (isset($recovered_uuids[$reference['referenced_uuid']])) {
                        $reference['referenced_uuid'] = $recovered_uuids[$reference['referenced_uuid']];
                    }
                }
            }
            foreach ($source_event[0]['EventReport'] as &$report) {
                unset($report['id'], $report['event_id']);
                $report['uuid'] = CakeText::uuid();
            }
            $results = [
                'results' => [
                    'Object' => $source_event[0]['Object'],
                    'Attribute' => $source_event[0]['Attribute'],
                    'EventReport' => $source_event[0]['EventReport']
                ]
            ];
            if ($this->_isRest()) {
                $this->loadModel('Log');
                $save_results = ['attributes' => 0, 'objects' => 0, 'eventReports' => 0];
                foreach ($results['results']['Attribute'] as $attribute) {
                    $this->Event->Attribute->captureAttribute($attribute, $target_id, $this->Auth->user());
                }
                foreach ($results['results']['Object'] as $object) {
                    $this->Event->Object->captureObject($object, $target_id, $this->Auth->user());
                }
                foreach ($results['results']['EventReport'] as $report) {
                    $this->Event->EventReport->captureReport($this->Auth->user(), $report, $target_id);
                }
                $event = $this->Event->fetchEvent(
                    $this->Auth->user(),
                    [
                        'eventid' => $target_id
                    ]
                );
                return $this->RestResponse->viewData($event, $this->response->type());
            }
            $event = $this->Event->handleMispFormatFromModuleResult($results);
            $event['Event'] = $target_event['Event'];
            $distributions = $this->Event->Attribute->distributionLevels;
            $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
            if (empty($sgs)) {
                unset($distributions[4]);
            }
            $this->set('distributions', $distributions);
            $this->set('sgs', $sgs);
            $this->set('event', $event);
            $this->set('title_for_layout', __('Event merge results'));
            $this->set('title', __('Event merge results'));
            $this->set('importComment', 'Merged from event ' . $source_id);
            $this->render('resolved_misp_format');
        } else {
            $this->set('target_event', $target_event);
            $this->set('title_for_layout', __('Merge data from event'));
        }
    }

    public function populate($id, $regenerateUUIDs=false)
    {
        if ($this->request->is('get') && $this->_isRest()) {
            return $this->RestResponse->describe('Events', 'populate', false, $this->response->type());
        }
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id, ['contain' => ['Orgc']]);
        if (!$event) {
            throw new NotFoundException(__('Invalid event'));
        }
        $id = $event['Event']['id']; // change possible event UUID with real ID
        // check if private and user not authorised to edit
        if (!$this->__canModifyEvent($event) && !($this->userRole['perm_sync'] && $this->_isRest())) {
            $message = __('You are not authorised to do that.');
            if ($this->_isRest()) {
                throw new ForbiddenException($message);
            } else {
                $this->Flash->error($message);
                $this->redirect(array('controller' => 'events', 'action' => 'index'));
            }
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if (isset($this->request->data['Event'])) {
                $regenerateUUIDs = $this->request->data['Event']['regenerate_uuids'] ?? false;
                $this->request->data = $this->request->data['Event'];
            }
            if (isset($this->request->data['json'])) {
                $this->request->data = $this->_jsonDecode($this->request->data['json']);
            }
            if (isset($this->request->data['Event'])) {
                $this->request->data = $this->request->data['Event'];
            }
            $eventToSave = $event;
            $capturedObjects = ['Attribute', 'Object', 'Tag', 'Galaxy', 'EventReport', 'Note', 'Opinion', 'Relationship',];
            foreach ($capturedObjects as $objectType) {
                if (!empty($this->request->data[$objectType])) {
                    if (!empty($regenerateUUIDs)) {
                        foreach ($this->request->data[$objectType] as $i => $obj) {
                            unset($this->request->data[$objectType][$i]['id']);
                            unset($this->request->data[$objectType][$i]['uuid']);
                            if ($objectType === 'Object' && !empty($this->request->data[$objectType][$i]['Attribute'])) {
                                foreach ($this->request->data[$objectType][$i]['Attribute'] as $j => $attr) {
                                    unset($this->request->data[$objectType][$i]['Attribute'][$j]['id']);
                                    unset($this->request->data[$objectType][$i]['Attribute'][$j]['uuid']);
                                }
                            }
                        }
                    }
                    $eventToSave['Event'][$objectType] = $this->request->data[$objectType];
                }
            }
            $eventToSave['Event']['published'] = 0;
            $eventToSave['Event']['timestamp'] = time();
            $result = $this->Event->_edit($eventToSave, $this->Auth->user(), $id);
            if ($this->_isRest()) {
                if ($result === true) {
                    // REST users want to see the newly created event
                    $metadata = $this->request->param('named.metadata');
                    $results = $this->Event->fetchEvent($this->Auth->user(), ['eventid' => $id, 'metadata' => $metadata]);
                    $event = $results[0];
                    return $this->__restResponse($event);
                } else {
                    $message = 'Error';
                    if ($this->_isRest()) {
                        if (isset($result['error'])) {
                            $errors = $result['error'];
                        } else {
                            $errors = $result;
                        }
                        return $this->RestResponse->saveFailResponse('Events', 'populate', $id, $errors, $this->response->type());
                    } else {
                        $this->set(array('message' => $message,'_serialize' => array('message')));  // $this->Event->validationErrors
                        $this->render('populate');
                    }
                    return false;
                }
            }
            if ($result) {
                $this->Flash->success(__('The event has been saved'));
                $this->redirect(array('action' => 'view', $id));
            } else {
                $this->Flash->error(__('The event could not be saved. Please, try again.'));
            }
        }
        $this->set('event', $event);
    }

    public function edit($id = null)
    {
        if ($this->request->is('get') && $this->_isRest()) {
            return $this->RestResponse->describe('Events', 'edit', false, $this->response->type());
        }
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id, ['contain' => ['Orgc', 'CryptographicKey']]);
        if (!$event) {
            throw new NotFoundException(__('Invalid event'));
        }
        $id = $event['Event']['id']; // change possible event UUID with real ID
        // check if private and user not authorised to edit
        if (!$this->__canModifyEvent($event) && !($this->userRole['perm_sync'] && $this->_isRest())) {
            $message = __('You are not authorised to do that.');
            if ($this->_isRest()) {
                throw new ForbiddenException($message);
            } else {
                $this->Flash->error($message);
                $this->redirect(array('controller' => 'events', 'action' => 'index'));
            }
        }
        if (
            !empty($event['Event']['protected']) &&
            $this->Auth->user('Role')['perm_sync'] &&
            !$this->Auth->user('Role')['perm_site_admin']
        ) {
            $pgp_signature = $this->request->header('x-pgp-signature');
            if (empty($pgp_signature)) {
                throw new MethodNotAllowedException(__('Protected event failed signature validation as no key was provided.'));
            }
            $raw_data = $this->request->input();
            if (
                !$this->Event->CryptographicKey->validateProtectedEvent(
                    $raw_data,
                    $this->Auth->user(),
                    $pgp_signature,
                    $event
                )
            ) {
                throw new MethodNotAllowedException(__('Protected event failed signature validation.'));
            }
        }
        if (!$this->_isRest()) {
            $this->Event->insertLock($this->Auth->user(), $id);
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $this->Event->set($event);
            if ($this->_isRest()) {
                if (isset($this->request->data['response'])) {
                    $this->request->data = $this->Event->updateXMLArray($this->request->data, true);
                } else {
                    $this->request->data = $this->Event->updateXMLArray($this->request->data, false);
                }
                // Workaround for different structure in XML/array than what CakePHP expects
                if (isset($this->request->data['response'])) {
                    $this->request->data = $this->request->data['response'];
                }
                if (!isset($this->request->data['Event'])) {
                    $this->request->data = array('Event' => $this->request->data);
                }
                $fast_update = $this->request->param('named.fast_update');
                if (!empty($this->request->data['Event']['fast_update'])) {
                    $fast_update = (bool)$this->request->data['Event']['fast_update'];
                }
                if ($fast_update) {
                    $this->Event->fast_update = true;
                    $this->Event->Attribute->fast_update = true;
                }
                $result = $this->Event->_edit($this->request->data, $this->Auth->user(), $id, null, null, false);
                if ($result === true) {
                    // REST users want to see the newly created event
                    $metadata = $this->request->param('named.metadata');
                    $results = $this->Event->fetchEvent($this->Auth->user(), ['eventid' => $id, 'metadata' => $metadata]);
                    $event = $results[0];
                    return $this->__restResponse($event);
                } else {
                    $message = 'Error';
                    if ($this->_isRest()) {
                        if (isset($result['error'])) {
                            $errors = $result['error'];
                        } else {
                            $errors = $result;
                        }
                        return $this->RestResponse->saveFailResponse('Events', 'edit', $id, $errors, $this->response->type());
                    } else {
                        $this->set(array('message' => $message,'_serialize' => array('message')));  // $this->Event->validationErrors
                        $this->render('edit');
                    }
                    return false;
                }
            }
            // say what fields are to be updated
            $fieldList = array('date', 'threat_level_id', 'analysis', 'info', 'published', 'distribution', 'timestamp', 'sharing_group_id', 'extends_uuid');

            // always force the org, but do not force it for admins
            if (!$this->_isSiteAdmin()) {
                // set the same org as existed before
                $this->request->data['Event']['org_id'] = $event['Event']['org_id'];
            }
            // we probably also want to remove the published flag
            $this->request->data['Event']['published'] = 0;
            $this->request->data['Event']['timestamp'] = time();
            if ($this->Event->save($this->request->data, true, $fieldList)) {
                $this->Flash->success(__('The event has been saved'));
                $this->redirect(array('action' => 'view', $id));
            } else {
                $this->Flash->error(__('The event could not be saved. Please, try again.'));
            }
        } else {
            $this->request->data = $event;
        }

        // combobox for distribution
        $distributions = array_keys($this->Event->distributionDescriptions);
        $distributions = $this->_arrayToValuesIndexArray($distributions);
        $this->set('distributions', $distributions);

        // even if the SG is not local, we still want the option to select the currently assigned SG
        $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $this->set('sharingGroups', $sgs);

        // tooltip for distribution
        $fieldDesc = array();
        $distributionLevels = $this->Event->distributionLevels;
        if (empty($sgs)) {
            unset($distributionLevels[4]);
        }
        $this->set('distributionLevels', $distributionLevels);
        foreach ($distributionLevels as $key => $value) {
            $fieldDesc['distribution'][$key] = $this->Event->distributionDescriptions[$key]['formdesc'];
        }

        // combobox for risks
        $threat_levels = $this->Event->ThreatLevel->find('all');
        $this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
        $fieldDesc['threat_level_id'] = Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.description');

        // combobox for analysis
        $this->set('sharingGroups', $sgs);
        // tooltip for analysis
        $analysisLevels = $this->Event->analysisLevels;
        foreach ($analysisLevels as $key => $value) {
            $fieldDesc['analysis'][$key] = $this->Event->analysisDescriptions[$key]['formdesc'];
        }
        $this->set('analysisLevels', $analysisLevels);
        $this->set('fieldDesc', $fieldDesc);
        $this->set('eventDescriptions', $this->Event->fieldDescriptions);
        $this->set('event', $event);
        $this->render('add');
    }

    public function delete($id = null)
    {
        if ($this->request->is(['post', 'put', 'delete'])) {
            if (isset($this->request->data['id'])) {
                $this->request->data['Event'] = $this->request->data;
            }
            if (!isset($id) && isset($this->request->data['Event']['id'])) {
                $idList = $this->request->data['Event']['id'];
                if (!is_array($idList)) {
                    if (is_numeric($idList) || Validation::uuid($idList)) {
                        $idList = array($idList);
                    } else {
                        $idList = $this->_jsonDecode($idList);
                    }
                }
                if (empty($idList)) {
                    throw new NotFoundException(__('Invalid input.'));
                }
            } else {
                $idList = array($id);
            }

            $fails = array();
            $successes = array();
            foreach ($idList as $eid) {
                $event = $this->Event->find('first', array(
                    'conditions' => Validation::uuid($eid) ? ['Event.uuid' => $eid] : ['Event.id' => $eid],
                    'recursive' => -1,
                ));
                if (empty($event)) {
                    $fails[] = $eid; // event not found
                    continue;
                }
                if (!$this->__canModifyEvent($event)) {
                    $fails[] = $eid; // user don't have permission to delete this event
                    continue;
                }
                $this->Event->insertLock($this->Auth->user(), $event['Event']['id']);
                if ($this->Event->quickDelete($event)) {
                    $successes[] = $eid;
                } else {
                    $fails[] = $eid;
                }
            }
            if (count($idList) === 1) {
                $message = empty($successes) ?  __('Event was not deleted.') : __('Event deleted.');
            } else {
                $message = '';
                if (!empty($successes)) {
                    $message .= __n('%s event deleted.', '%s events deleted.', count($successes), count($successes));
                }
                if (!empty($fails)) {
                    $message .= count($fails) . ' event(s) could not be deleted due to insufficient privileges or the event not being found.';
                }
            }
            if ($this->_isRest()) {
                if (!empty($successes)) {
                    return $this->RestResponse->saveSuccessResponse('Events', 'delete', $id, $this->response->type(), $message);
                } else {
                    return $this->RestResponse->saveFailResponse('Events', 'delete', false, $message, $this->response->type());
                }
            } else {
                if (!empty($successes)) {
                    $this->Flash->success($message);
                } else {
                    $this->Flash->error($message);
                }
                $this->redirect(array('action' => 'index'));
            }
        } else {
            $eventList = is_numeric($id) ? [$id] : $this->_jsonDecode($id);
            $this->request->data['Event']['id'] = json_encode($eventList);
            $this->set('idArray', $eventList);
            $this->render('ajax/eventDeleteConfirmationForm');
        }
    }

    public function unpublish($id = null)
    {
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        $this->Event->id = $id;
        $this->Event->recursive = -1;
        $event = $this->Event->read(null, $id);
        if (!$this->__canModifyEvent($this->Event->data)) {
            throw new ForbiddenException(__('You do not have the permission to do that.'));
        }
        $this->Event->insertLock($this->Auth->user(), $id);
        if ($this->request->is('post') || $this->request->is('put')) {
            $fieldList = array('published', 'id', 'info');
            $event['Event']['published'] = 0;
            $result = $this->Event->save($event, array('fieldList' => $fieldList));
            if ($result) {
                $message = __('Event unpublished.');
                $kafkaTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
                if (Configure::read('Plugin.Kafka_enable') && Configure::read('Plugin.Kafka_event_publish_notifications_enable') && !empty($kafkaTopic)) {
                    $kafkaPubTool = $this->Event->getKafkaPubTool();
                    $params = array('eventid' => $id);
                    if (Configure::read('Plugin.Kafka_include_attachments')) {
                        $params['includeAttachments'] = 1;
                    }
                    $pubEvent = $this->Event->fetchEvent($this->Auth->user(), $params);
                    if (!empty($pubEvent)) {
                        $kafkaPubTool->publishJson($kafkaTopic, $pubEvent[0], 'unpublish');
                    }
                }
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('events', 'unpublish', $id, false, $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(array('action' => 'view', $id));
                }
            } else {
                throw new MethodNotAllowedException('Could not unpublish event.');
            }
        } else {
            $this->set('id', $id);
            $this->set('type', 'unpublish');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    public function publishSightings($id = null)
    {
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $result = $this->Event->publishSightingsRouter($event['Event']['id'],  $this->Auth->user());
            if (!Configure::read('MISP.background_jobs')) {
                if (!is_array($result)) {
                    // redirect to the view event page
                    $message = 'Sightings published';
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $message = sprintf('Sightings published but not pushed to %s, re-try later. If the issue persists, make sure that the correct sync user credentials are used for the server link and that the sync user on the remote server has authentication privileges.', $resultString);
                }
            } else {
                // update the DB to set the published flag
                // for background jobs, this should be done already
                $fieldList = array('id', 'info', 'sighting_timestamp');
                $event['Event']['sighting_timestamp'] = time();
                $this->Event->save($event, array('fieldList' => $fieldList));
                $message = 'Job queued';
            }
            if ($this->_isRest()) {
                $this->set('name', 'Publish Sightings');
                $this->set('message', $message);
                if (!empty($errors)) {
                    $this->set('errors', $errors);
                }
                $this->set('url', $this->baseurl . '/events/publishSightings/' . $event['Event']['id']);
                $this->set('id', $event['Event']['id']);
                $this->set('_serialize', array('name', 'message', 'url', 'id', 'errors'));
            } else {
                $this->Flash->success($message);
                $this->redirect(array('action' => 'view', $event['Event']['id']));
            }
        } else {
            $this->set('id', $id);
            $this->set('type', 'publishSightings');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    // Publishes the event without sending an alert email
    public function publish($id = null)
    {
        $event = $this->__prepareForPublish($id);

        // only allow form submit CSRF protection.
        if ($this->request->is('post') || $this->request->is('put')) {
            $errors = array();
            // Performs all the actions required to publish an event
            $result = $this->Event->publishRouter($event['Event']['id'], null, $this->Auth->user());
            if (!Configure::read('MISP.background_jobs')) {
                if (!is_array($result)) {
                    if ($result === true) {
                        $message = __('Event published without alerts');
                    } else {
                        $message = __('Event publishing failed due to a blocking module failing. The reason for the failure: %s', $result);
                        $errors['Module'] = 'Module failure.';
                    }
                } else {
                    $errors['failed_servers'] = $result;
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $message = __('Event published but not pushed to %s, re-try later. If the issue persists, make sure that the correct sync user credentials are used for the server link and that the sync user on the remote server has authentication privileges.', $resultString);
                }
            } else {
                $message = 'Job queued';
            }
            if ($this->_isRest()) {
                if (!empty($errors)) {
                    return $this->RestResponse->saveFailResponse('Events', 'publish', $event['Event']['id'], $errors);
                } else {
                    return $this->RestResponse->saveSuccessResponse('Events', 'publish', $event['Event']['id'], false, $message);
                }
            } else {
                if (!empty($errors)) {
                    $this->Flash->error($message);
                } else {
                    $this->Flash->success($message);
                }
                $this->redirect(array('action' => 'view', $event['Event']['id']));
            }
        } else {
            $servers = $this->Event->listServerToPush($event);
            $this->set('id', $event['Event']['id']);
            $this->set('servers', $servers);
            $this->set('type', 'publish');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    // Send out an alert email to all the users that wanted to be notified.
    // Users with a GnuPG key will get the mail encrypted, other users will get the mail unencrypted
    public function alert($id = null)
    {
        $event = $this->__prepareForPublish($id);

        // only allow form submit CSRF protection
        if ($this->request->is('post') || $this->request->is('put')) {
            $errors = array();
            // send out the email
            $emailResult = $this->Event->sendAlertEmailRouter($event['Event']['id'], $this->Auth->user(), $event['Event']['publish_timestamp']);
            if (is_bool($emailResult) && $emailResult == true) {
                // Performs all the actions required to publish an event
                $result = $this->Event->publishRouter($event['Event']['id'], null, $this->Auth->user());
                if (!is_array($result)) {
                    // redirect to the view event page
                    if (Configure::read('MISP.background_jobs')) {
                        $message = 'Job queued.';
                    } else {
                        $message = 'Email sent to all participants.';
                    }
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $message = __('Not published given no connection to %s but email sent to all participants.', $resultString);
                }

            } elseif (!is_bool($emailResult)) {
                // Performs all the actions required to publish an event
                $result = $this->Event->publishRouter($event['Event']['id'], null, $this->Auth->user());
                if (!is_array($result)) {
                    if ($result === true) {
                        $message = __('Published but no email sent given GnuPG is not configured.');
                        $errors['GnuPG'] = 'GnuPG not set up.';
                    } else {
                        $message = $result;
                        $errors['Module'] = 'Module failure.';
                    }
                    // redirect to the view event page
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $errors['GnuPG'] = 'GnuPG not set up.';
                    $message = __('Not published given no connection to %s but no email sent given GnuPG is not configured.', $resultString);
                }
            } else {
                $message = 'Sending of email failed';
                $errors['email'] = 'The sending of emails failed.';
            }
            if ($this->_isRest()) {
                if (!empty($errors)) {
                    return $this->RestResponse->saveFailResponse('Events', 'alert', $event['Event']['id'], $errors);
                } else {
                    return $this->RestResponse->saveSuccessResponse('Events', 'alert', $event['Event']['id'], false, $message);
                }
            } else {
                if (isset($errors['failed_servers'])) {
                    $this->Flash->error($message);
                } else {
                    $this->Flash->success($message);
                }
                $this->redirect(array('action' => 'view', $event['Event']['id']));
            }
        } else {
            $servers = $this->Event->listServerToPush($event);
            $this->set('id', $event['Event']['id']);
            $this->set('servers', $servers);
            $this->set('type', 'alert');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    /**
     * @param int|string $id Event ID or UUID
     * @return array
     */
    private function __prepareForPublish($id)
    {
        if (empty($id)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        $event = $this->Event->find('first', [
            'conditions' => Validation::uuid($id) ? ['Event.uuid' => $id] : ['Event.id' => $id],
            'recursive' => -1,
            'fields' => ['id', 'info', 'publish_timestamp', 'orgc_id', 'user_id'],
        ]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        if (!$this->__canPublishEvent($event)) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if (!$this->_isRest()) {
            $this->Event->insertLock($this->Auth->user(), $event['Event']['id']);

            if ($this->request->is('post') || $this->request->is('put')) {
                $publishable = $this->Event->checkIfPublishable($event['Event']['id']);
                if ($publishable !== true) {
                    $this->Flash->error(__('Could not publish event - no tag for required taxonomies missing: %s', implode(', ', $publishable)));
                    $this->redirect(['action' => 'view', $event['Event']['id']]);
                }
            }
        }
        if (
            Configure::read('MISP.block_publishing_for_same_creator', false) &&
            $this->Auth->user()['id'] == $event['Event']['user_id']
        ) {
            $message = __('Could not publish the event, the publishing user cannot be the same as the event creator as per this instance\'s configuration.');
            if (!$this->_isRest()) {
                $this->Flash->error($message);
            }
            throw new MethodNotAllowedException($message);
        }

        return $event;
    }

    // Send out an contact email to the person who posted the event.
    // Users with a GnuPG key will get the mail encrypted, other users will get the mail unencrypted
    public function contact($id = null)
    {
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id, ['contain' => ['Orgc']]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        // User has filled in his contact form, send out the email.
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['Event'])) {
                $this->request->data = array('Event' => $this->request->data);
            }
            $message = $this->request->data['Event']['message'];
            if (empty($message)) {
                $error = __('You must specify a message.');
                if ($this->_isRest()) {
                    throw new MethodNotAllowedException($error);
                } else {
                    $this->Flash->error($error);
                    $this->redirect(array('action' => 'contact', $event['Event']['id']));
                }
            }

            $creator_only = false;
            if (isset($this->request->data['Event']['person'])) {
                $creator_only = $this->request->data['Event']['person'];
            }
            $user = $this->Auth->user();
            $user = $this->Event->User->fillKeysToUser($user);

            $success = $this->Event->sendContactEmailRouter($event['Event']['id'], $message, $creator_only, $user);
            if ($success) {
                $return_message = __('Email sent to the reporter.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Events', 'contact', $event['Event']['id'], $this->response->type(), $return_message);
                } else {
                    $this->Flash->success($return_message);
                    // redirect to the view event page
                    $this->redirect(array('action' => 'view', $event['Event']['id']));
                }
            } else {
                $return_message = __('Sending of email failed.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Events', 'contact', $event['Event']['id'], $return_message, $this->response->type());
                } else {
                    $this->Flash->error($return_message, 'default', array(), 'error');
                    // redirect to the view event page
                    $this->redirect(array('action' => 'view', $event['Event']['id']));
                }
            }
        }
        $this->set('event', $event);
        $this->set('mayModify', $this->__canModifyEvent($event));
    }

    public function automation($legacy = false)
    {
        // Simply display a static view
        App::uses('BroExport', 'Export');
        $export = new BroExport();
        $temp = $export->mispTypes;
        $broTypes = array('all' => 'All types listed below.');
        foreach ($temp as $broType => $mispTypes) {
            foreach ($mispTypes as $mT) {
                $broTypes[$broType][] = $mT[0];
            }
            $broTypes[$broType] = implode(', ', $broTypes[$broType]);
        }
        $this->loadModel('Server');
        $this->set('command_line_functions', $this->Server->command_line_functions);
        $this->set('broTypes', $broTypes);
        // generate the list of Attribute types
        $this->loadModel('MispAttribute');
        $this->set('sigTypes', array_keys($this->MispAttribute->typeDefinitions));
        $this->loadModel('Server');
        if (empty(Configure::read('Security.advanced_authkeys'))) {
            $authkey = $this->Event->User->find('first', [
                'fields' => ['authkey'],
                'conditions' => ['User.id' => $this->Auth->user()['id']],
                'recursive' => -1
            ])['User']['authkey'];
            $this->set('authkey', $authkey);
        }
        $rpzSettings = $this->Server->retrieveCurrentSettings('Plugin', 'RPZ_');
        $this->set('rpzSettings', $rpzSettings);
        $this->set('hashTypes', array_keys(MispAttribute::FILE_HASH_TYPES));
        if ($legacy) {
            $this->render('legacy_automation');
        }
    }

    public function export()
    {
        $filesize_units = array('B', 'KB', 'MB', 'GB', 'TB');
        if ($this->_isSiteAdmin()) {
            $this->Flash->info(__('Warning, you are logged in as a site admin, any export that you generate will contain the FULL UNRESTRICTED data-set. If you would like to generate an export for your own organisation, please log in with a different user.'));
        }
        // Check if the background jobs are enabled - if not, fall back to old export page.
        if (Configure::read('MISP.background_jobs') && !Configure::read('MISP.disable_cached_exports', true)) {
            $now = time();

            // as a site admin we'll use the ADMIN identifier, not to overwrite the cached files of our own org with a file that includes too much data.
            $org_name = $this->_isSiteAdmin() ? 'ADMIN' : $this->Auth->user('Organisation')['name'];
            $conditions = $this->Event->createEventConditions($this->Auth->user());
            $this->Event->recursive = -1;
            $newestEvent = $this->Event->find('first', array(
                'conditions' => $conditions,
                'fields' => 'timestamp',
                'order' => 'Event.timestamp DESC',
            ));
            $newestEventPublished = $this->Event->find('first', array(
                'conditions' => array('AND' => array($conditions, array('published' => 1))),
                'fields' => 'timestamp',
                'order' => 'Event.timestamp DESC',
            ));
            $this->loadModel('Job');
            $exportTypes = $this->Event->exportTypes();
            foreach ($exportTypes as $k => $type) {
                if ($type['requiresPublished']) {
                    $tempNewestEvent = $newestEventPublished;
                } else {
                    $tempNewestEvent = $newestEvent;
                }
                $job = $this->Job->find('first', array(
                        'fields' => array('id', 'progress'),
                        'conditions' => array(
                                'job_type' => 'cache_' . $k,
                                'org_id' => $this->_isSiteAdmin() ? 0 : $this->Auth->user('org_id')
                            ),
                        'order' => array('Job.id' => 'desc')
                ));
                $dir = new Folder(APP . 'tmp/cached_exports/' . $k, true);
                if ($k === 'text') {
                    // Since all of the text export files are generated together, we might as well just check for a single one md5.
                    $file = new File($dir->pwd() . DS . 'misp.text_md5.' . $org_name . $type['extension']);
                } else {
                    $file = new File($dir->pwd() . DS . 'misp.' . $k . '.' . $org_name . $type['extension']);
                }
                if (!$file->readable()) {
                    if (empty($tempNewestEvent)) {
                        $lastModified = 'No valid events';
                        $exportTypes[$k]['recommendation'] = 0;
                    } else {
                        $lastModified = 'N/A';
                        $exportTypes[$k]['recommendation'] = 1;
                    }
                } else {
                    $filesize = $file->size();
                    $filesize_unit_index = 0;
                    while ($filesize > 1024) {
                        $filesize_unit_index++;
                        $filesize = $filesize / 1024;
                    }
                    $exportTypes[$k]['filesize'] = round($filesize, 1) . $filesize_units[$filesize_unit_index];
                    $fileChange = $file->lastChange();
                    $lastModified = $this->__timeDifference($now, $fileChange);
                    if (empty($tempNewestEvent) || $fileChange > $tempNewestEvent['Event']['timestamp']) {
                        if (empty($tempNewestEvent)) {
                            $lastModified = 'No valid events';
                        }
                        $exportTypes[$k]['recommendation'] = 0;
                    } else {
                        $exportTypes[$k]['recommendation'] = 1;
                    }
                }

                $exportTypes[$k]['lastModified'] = $lastModified;
                if (!empty($job)) {
                    $exportTypes[$k]['job_id'] = $job['Job']['id'];
                    $exportTypes[$k]['progress'] = $job['Job']['progress'];
                } else {
                    $exportTypes[$k]['job_id'] = -1;
                    $exportTypes[$k]['progress'] = 0;
                }
            }
        } else {
            $exportTypes = [];
        }

        $this->set('sigTypes', array_keys($this->Event->Attribute->typeDefinitions));
        $this->set('export_types', $exportTypes);
    }

    public function downloadExport($type, $extra = null)
    {
        if (Configure::read('MISP.disable_cached_exports', true)) {
            throw new MethodNotAllowedException(__('This feature is currently disabled'));
        }
        if ($this->_isSiteAdmin()) {
            $org = 'ADMIN';
        } else {
            $org = $this->Auth->user('Organisation')['name'];
        }
        $this->autoRender = false;
        if ($extra != null) {
            $extra = '_' . $extra;
        }
        $exportType = $this->Event->exportTypes()[$type];
        $this->response->type($exportType['extension']);
        $path = 'tmp/cached_exports/' . $type . DS . 'misp.' . strtolower($exportType['type']) . $extra . '.' . $org . $exportType['extension'];
        $this->response->file($path, array('download' => true));
    }

    private function __timeDifference($now, $then)
    {
        $periods = array("second", "minute", "hour", "day", "week", "month", "year");
        $lengths = array("60","60","24","7","4.35","12");
        $difference = $now - $then;
        for ($j = 0; $difference >= $lengths[$j] && $j < count($lengths)-1; $j++) {
            $difference /= $lengths[$j];
        }
        $difference = round($difference);
        if ($difference != 1) {
            $periods[$j].= "s";
        }
        return $difference . " " . $periods[$j] . " ago";
    }

    public function restSearchExport($id = null, $returnFormat = null)
    {
        if ($returnFormat === null) {
            $exportFormats = [
                'attack' => __('Attack matrix'),
                'attack-sightings' => __('Attack matrix by sightings'),
                'context' => __('Aggregated context data'),
                'context-markdown' => __('Aggregated context data as Markdown'),
                'csv' => __('CSV'),
                'hashes' => __('Hashes'),
                'hosts' => __('Hosts file'),
                'json' => __('MISP JSON'),
                'netfilter' => __('Netfilter'),
                'opendata' => __('Open data'),
                'openioc' => __('OpenIOC'),
                'rpz' => __('RPZ'),
                'snort' => __('Snort rules'),
                'stix' => __('STIX 1 XML'),
                'stix-json' => __('STIX 1 JSON'),
                'stix2' => __('STIX 2'),
                'suricata' => __('Suricata rules'),
                'text' => __('Text file'),
                'xml' => __('MISP XML'),
                'yara' => __('YARA rules'),
                'yara-json' => __('YARA rules (JSON)'),
            ];

            $idList = is_numeric($id) ? [$id] : $this->_jsonDecode($id);
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }
            $this->set('idList', $idList);
            $this->set('exportFormats', $exportFormats);
            $this->render('ajax/eventRestSearchExportConfirmationForm');
        } else {
            $returnFormat = !isset($this->Event->validFormats[$returnFormat]) ? 'json' : $returnFormat;
            $idList = $id;
            if (!is_array($idList)) {
                if (is_numeric($idList) || Validation::uuid($idList)) {
                    $idList = array($idList);
                } else {
                    $idList = $this->_jsonDecode($idList);
                }
            }
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }
            $filters = [
                'eventid' => $idList,
                'published' => [true, false], // fetch published and unpublished events
            ];

            $elementCounter = 0;
            $renderView = false;
            $responseType = $this->Event->validFormats[$returnFormat][0];
            $final = $this->Event->restSearch($this->Auth->user(), $returnFormat, $filters, false, false, $elementCounter, $renderView);
            if ($renderView) {
                $final = JsonTool::decode($final->intoString());
                $this->set($final);
                $this->set('responseType', $responseType);
                $this->set('returnFormat', $returnFormat);
                $this->set('renderView', $renderView);
                $this->render('/Events/eventRestSearchExportResult');
            } else {
                $filename = $this->RestSearch->getFilename($filters, 'Event', $responseType);
                return $this->RestResponse->viewData($final, $responseType, false, true, $filename, [
                    'X-Result-Count' => $elementCounter,
                    'X-Export-Module-Used' => $returnFormat,
                    'X-Response-Format' => $responseType
                ]);
            }
        }
    }

    public function xml($key, $eventid = false, $withAttachment = false, $tags = false, $from = false, $to = false, $last = false)
    {
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'key', 'eventid', 'withAttachment', 'tags', 'from', 'to', 'last'
            ),
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => func_get_args(),
            'injectedParams' => array(
                'returnFormat' => 'xml'
            )
        ));
        return $this->restSearch();
    }

    public function nids()
    {
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'format', 'key', 'id', 'continue', 'tags', 'from', 'to', 'last',
                'type', 'enforceWarninglist', 'includeAllTags', 'eventid'
            ),
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => func_get_args()
        ));
        if (empty($this->_legacyParams['returnFormat'])) {
            $this->_legacyParams['returnFormat'] = 'suricata';
        }
        return $this->restSearch();
    }

    public function hids($type)
    {
        $typeMappings = array(
            'md5' => array('malware-sample', 'md5', 'filename|md5'),
            'sha1' => array('sha1', 'filename|sha1'),
            'sha256' => array('sha256', 'filename|sha256')
        );
        $ordered_url_params = func_get_args();
        unset($ordered_url_params[0]);
        $ordered_url_params = array_values($ordered_url_params);
        $this->scopeOverride = 'Attribute';
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'key', 'id', 'withAttachment', 'tags', 'from', 'to', 'last'
            ),
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => $ordered_url_params,
            'injectedParams' => array(
                'returnFormat' => 'hashes',
                'type' => (isset($typeMappings[$type])) ? $typeMappings[$type] : $type
            )
        ));
        return $this->restSearch();
    }

    // DEPRECATED - use restSearch with "returnFormat":"csv"
    public function csv($key)
    {
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'key', 'eventid', 'ignore', 'tags', 'category', 'type', 'includeContext',
                'from', 'to', 'last', 'headerless', 'enforceWarninglist', 'value', 'timestamp'
            ),
            'key' => $key,
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => func_get_args(),
            'injectedParams' => array(
                'returnFormat' => 'csv',
                'to_ids' => '1',
                'published' => '1'
            )
        ));
        return $this->restSearch();
    }

    public function _addIOCFile($id)
    {
        if (!empty($this->data) && $this->data['Event']['submittedioc']['size'] > 0 &&
                is_uploaded_file($this->data['Event']['submittedioc']['tmp_name'])) {
            if (!$this->Event->checkFilename($this->data['Event']['submittedioc']['name'])) {
                throw new Exception(__('Filename not allowed.'));
            }

            // Load event and populate the event data
            $this->Event->id = $id;
            $this->Event->recursive = -1;
            if (!$this->Event->exists()) {
                throw new NotFoundException(__('Invalid event'));
            }
            $this->Event->read(null, $id);
            $saveEvent['Event'] = $this->Event->data['Event'];
            $saveEvent['Event']['published'] = false;
            $dist = '5';
            if (Configure::read('MISP.default_attribute_distribution') != null) {
                if (Configure::read('MISP.default_attribute_distribution') === 'event') {
                    $dist = '5';
                } else {
                    $dist = '';
                    $dist .= Configure::read('MISP.default_attribute_distribution');
                }
            }
            // read XML
            App::uses('FileAccessTool', 'Tools');
            $xmlFileData = FileAccessTool::readFromFile($this->data['Event']['submittedioc']['tmp_name'], $this->data['Event']['submittedioc']['size']);
            $event = $this->IOCImport->readXML($xmlFileData, $id, $dist, $this->data['Event']['submittedioc']['name']);

            // make some changes to have $saveEvent in the format that is needed to save the event together with its attributes
            $fails = $event['Fails'];
            $saveEvent['Attribute'] = $event['Attribute'];
            // we've already stored these elsewhere, unset them so we can extract the event related data
            unset($event['Attribute']);
            unset($event['Fails']);

            // add the original openIOC file as an attachment
            $saveEvent['Attribute'][] = array(
                'category' => 'External analysis',
                'uuid' =>  CakeText::uuid(),
                'type' => 'attachment',
                'sharing_group_id' => '0',
                'value' => $this->data['Event']['submittedioc']['name'],
                'to_ids' => false,
                'distribution' => $dist,
                'data' => base64_encode($xmlFileData),
                'comment' => 'OpenIOC import source file'
            );

            // LATER we might want to let an ioc create the event data automatically in a later version
            // save the event related data into $saveEvent['Event']
            //$saveEvent['Event'] = $event;
            //$saveEvent['Event']['id'] = $id;

            $fieldList = array(
                    'Event' => array('published', 'timestamp'),
                    'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'distribution', 'timestamp', 'comment', 'sharing_group_id')
            );
            // Save it all
            $saveResult = $this->Event->saveAssociated($saveEvent, array('validate' => true, 'fieldList' => $fieldList));
            // set stuff for the view and render the showIOCResults view.
            $this->set('attributes', $saveEvent['Attribute']);
            if (isset($fails)) {
                $this->set('fails', $fails);
            }
            $this->set('eventId', $id);
            $this->set('graph', $event['Graph']);
            $this->set('saveEvent', $saveEvent);
            $this->render('showIOCResults');
        }
    }

    public function downloadOpenIOCEvent($key, $eventid, $enforceWarninglist = false)
    {
        // return a downloadable text file called misp.openIOC.<eventId>.ioc for individual events
        // TODO implement mass download of all events - maybe in a zip file?
        $this->response->type('text');  // set the content type
        if ($eventid == null) {
            throw new Exception(__('Not yet implemented'));
        }
        $this->layout = 'text/default';

        if ($key != 'download') {
            $user = $this->_checkAuthUser($key);
            if (!$user) {
                throw new UnauthorizedException(__('This authentication key is not authorized to be used for exports. Contact your administrator.'));
            }
        } else {
            if (!$this->Auth->user('id')) {
                throw new UnauthorizedException(__('You have to be logged in to do that.'));
            }
        }

        // get the event if it exists and load it together with its attributes
        $this->Event->id = $eventid;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid event or not authorised.'));
        }
        $event = $this->Event->fetchEvent($this->Auth->user(), $options = array('eventid' => $eventid, 'to_ids' => 1, 'enforceWarninglist' => $enforceWarninglist));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event or not authorised.'));
        }
        $this->loadModel('Allowedlist');
        $temp = $this->Allowedlist->removeAllowedlistedFromArray(array($event[0]), false);
        $event = $temp[0];

        // send the event and the vars needed to check authorisation to the Component
        App::uses('IOCExportTool', 'Tools');
        $this->IOCExport = new IOCExportTool();
        $final = $this->IOCExport->buildAll($this->Auth->user(), $event);
        $this->response->type('xml');
        $this->autoRender = false;
        $this->response->body($final);
        $this->response->download('misp.openIOC' . $eventid . '.ioc');
        return $this->response;
    }

    public function proposalEventIndex()
    {
        $this->loadModel('ShadowAttribute');
        $conditions = array('ShadowAttribute.deleted' => 0);
        if (!$this->_isSiteAdmin()) {
            $conditions[] = array('ShadowAttribute.event_org_id' => $this->Auth->user('org_id'));
        }
        $result = $this->ShadowAttribute->find('column', [
            'fields' => ['event_id'],
            'conditions' => $conditions,
            'unique' => true,
        ]);
        $this->Event->recursive = -1;

        if (empty($result)) {
            $conditions = array('Event.id' => -1);
        } else {
            $conditions = array('Event.id' => $result);
        }
        $this->paginate = array(
            'fields' => array('Event.id', 'Event.org_id', 'Event.orgc_id', 'Event.publish_timestamp', 'Event.distribution', 'Event.info', 'Event.date', 'Event.published'),
            'conditions' => $conditions,
            'contain' => array(
                'User' => array(
                    'fields' => array(
                        'User.email'
                )),
                'ShadowAttribute'=> array(
                    'fields' => array(
                        'ShadowAttribute.id', 'ShadowAttribute.org_id', 'ShadowAttribute.event_id'
                    ),
                    'conditions' => array(
                        'ShadowAttribute.deleted' => 0
                    ),
                ),
            )
        );
        $events = $this->paginate();
        $orgIds = array();
        foreach ($events as $k => $event) {
            $orgs = array();
            foreach ($event['ShadowAttribute'] as $sa) {
                if (!in_array($sa['org_id'], $orgs)) {
                    $orgs[] = $sa['org_id'];
                }
                if (!in_array($sa['org_id'], $orgIds)) {
                    $orgIds[] = $sa['org_id'];
                }
            }
            $events[$k]['orgArray'] = $orgs;
            $events[$k]['Event']['proposal_count'] = count($event['ShadowAttribute']);
        }
        $orgs = $this->Event->Orgc->find('list', array(
            'conditions' => array('Orgc.id' => $orgIds),
            'fields' => array('Orgc.id', 'Orgc.name')
        ));
        $this->set('orgs', $orgs);
        $this->set('events', $events);
        $this->set('eventDescriptions', $this->Event->fieldDescriptions);
        $this->set('analysisLevels', $this->Event->analysisLevels);
        $this->set('distributionLevels', $this->Event->distributionLevels);
    }

    public function reportValidationIssuesEvents()
    {
        // search for validation problems in the events
        if (!self::_isSiteAdmin()) {
            throw new NotFoundException();
        }
        $results = $this->Event->reportValidationIssuesEvents();
        $result = $results[0];
        $count = $results[1];
        $this->set('result', $result);
        $this->set('count', $count);
    }

    public function addTag($id = false, $tag_id = false)
    {
        $rearrangeRules = array(
            'request' => false,
            'Event' => false,
            'tag_id' => 'tag',
            'event_id' => 'event',
            'id' => 'event'
        );
        $RearrangeTool = new RequestRearrangeTool();
        $this->request->data = $RearrangeTool->rearrangeArray($this->request->data, $rearrangeRules);
        if ($id === false) {
            $id = $this->request->data['event'];
        }
        $conditions = ['Event.id' => $id];
        if (Validation::uuid($id)) {
            $conditions = ['Event.uuid' => $id];
        }
        $event = $this->Event->find(
            'first',
            [
                'recursive' => -1,
                'conditions' => $conditions
            ]
        );
        if (empty($event)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid event.')), 'status'=>200, 'type' => 'json'));
        }
        $id = $event['Event']['id'];
        $local = !empty($this->params['named']['local']);
        if (!$this->request->is('post')) {
            $this->set('local', $local);
            $this->set('object_id', $id);
            $this->set('scope', 'Event');
            $this->layout = false;
            $this->autoRender = false;
            $this->render('/Events/add_tag');
        } else {
            if ($tag_id === false) {
                $tag_id = $this->request->data['tag'];
            }
            if (!$this->__canModifyTag($event, $local)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
            }
            if (!is_numeric($tag_id)) {
                if (preg_match('/^collection_[0-9]+$/i', $tag_id)) {
                    $tagChoice = explode('_', $tag_id)[1];
                    $this->loadModel('TagCollection');
                    $tagCollection = $this->TagCollection->fetchTagCollection($this->Auth->user(), array('conditions' => array('TagCollection.id' => $tagChoice)));
                    if (empty($tagCollection)) {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag Collection.')), 'status'=>200, 'type' => 'json'));
                    }
                    $tag_id_list = array();
                    foreach ($tagCollection[0]['TagCollectionTag'] as $tagCollectionTag) {
                        $tag_id_list[] = $tagCollectionTag['tag_id'];
                    }
                } else {
                    $tag_ids = json_decode($tag_id);
                    if ($tag_ids !== null) { // can decode json
                        $tag_id_list = array();
                        foreach ($tag_ids as $tag_id) {
                            if (preg_match('/^collection_[0-9]+$/i', $tag_id)) {
                                $tagChoice = explode('_', $tag_id)[1];
                                $this->loadModel('TagCollection');
                                $tagCollection = $this->TagCollection->fetchTagCollection($this->Auth->user(), array('conditions' => array('TagCollection.id' => $tagChoice)));
                                if (empty($tagCollection)) {
                                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag Collection.')), 'status'=>200, 'type' => 'json'));
                                }
                                foreach ($tagCollection[0]['TagCollectionTag'] as $tagCollectionTag) {
                                    $tag_id_list[] = $tagCollectionTag['tag_id'];
                                }
                            } else {
                                $tag_id_list[] = $tag_id;
                            }
                        }
                    } else {
                        $tagId = $this->Event->EventTag->Tag->lookupTagIdForUser($this->Auth->user(), trim($tag_id));
                        if (empty($tagId)) {
                            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status'=>200, 'type' => 'json'));
                        }
                        $tag_id = $tagId;
                    }
                }
            }
            $this->autoRender = false;
            $success = 0;
            $fails = [];
            if (empty($tag_id_list)) {
                $tag_id_list = array($tag_id);
            }

            if (empty($tag_id_list)) {
                return new CakeResponse(array('body' => json_encode(['saved' => false, 'errors' => __('Nothing to add.')]), 'status' => 200, 'type' => 'json'));
            }

            $this->loadModel('Taxonomy');
            foreach ($tag_id_list as $tag_id) {
                $conditions = $this->Event->EventTag->Tag->createConditions($this->Auth->user());
                $conditions['Tag.id'] = $tag_id;
                $tag = $this->Event->EventTag->Tag->find('first', array(
                    'conditions' => $conditions,
                    'recursive' => -1,
                    'fields' => array('Tag.name', 'Tag.local_only')
                ));
                if (!$tag) {
                    $fails[$tag_id] = __('Tag not found.');
                    continue;
                }
                $found = $this->Event->EventTag->hasAny([
                    'event_id' => $id,
                    'tag_id' => $tag_id
                ]);
                if ($found) {
                    $fails[$tag_id] = __('Tag is already attached to this event.');
                    continue;
                }
                $tagsOnEvent = $this->Event->EventTag->find('column', array(
                    'conditions' => array(
                        'EventTag.event_id' => $id,
                        'EventTag.local' => $local
                    ),
                    'contain' => 'Tag',
                    'fields' => array('Tag.name'),
                    'recursive' => -1
                ));
                $exclusiveTestPassed = $this->Taxonomy->checkIfNewTagIsAllowedByTaxonomy($tag['Tag']['name'], $tagsOnEvent);
                if (!$exclusiveTestPassed) {
                    $fails[$tag_id] = __('Tag is not allowed due to taxonomy exclusivity settings');
                    continue;
                }
                if ($tag['Tag']['local_only'] && !$local) {
                    $fails[$tag_id] = __('Invalid Tag. This tag can only be set as a local tag.');
                    continue;
                }
                $this->Event->EventTag->create();
                if ($this->Event->EventTag->save(array('event_id' => $id, 'tag_id' => $tag_id, 'local' => $local))) {
                    if (!$local) {
                        $this->Event->unpublishEvent($event);
                    }
                    $log = ClassRegistry::init('Log');
                    $log->createLogEntry(
                        $this->Auth->user(),
                        'tag',
                        'Event',
                        $id,
                        sprintf(
                            'Attached%s tag (%s) "%s" to event (%s)',
                            $local ? ' local' : '',
                            $tag_id,
                            $tag['Tag']['name'],
                            $id
                        ),
                        sprintf(
                            'Event (%s) tagged as Tag (%s)%s',
                            $id,
                            $tag_id,
                            $local ? ' locally' : ''
                        )
                    );
                    ++$success;
                } else {
                    $fails[$tag_id] = __('Tag could not be added.');
                }
            }

            if ($success && empty($fails)) {
                $body = ['saved' => true, 'success' => __n('Tag added.', 'Tags added.', $success), 'check_publish' => true];
            } else if ($success && !empty($fails)) {
                $message = __n('Tag added', '%s tags added', $success, $success);
                $message .= __(', but %s could not be added: %s', count($fails), implode(', ', $fails));
                $body = ['saved' => true, 'success' => $message, 'check_publish' => true];
            } else {
                $body = array('saved' => false, 'errors' => implode(', ', $fails));
            }
            return new CakeResponse(array('body' => json_encode($body), 'status' => 200, 'type' => 'json'));
        }
    }

    public function removeTag($id = false, $tag_id = false, $galaxy = false)
    {
        if (!$this->request->is('post')) {
            $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
            if (!$event) {
                throw new NotFoundException(__('Invalid event.'));
            }
            $eventTag = $this->Event->EventTag->find('first', array(
                'conditions' => array(
                    'event_id' => $event['Event']['id'],
                    'tag_id' => $tag_id,
                ),
                'contain' => ['Tag'],
                'recursive' => -1,
            ));
            if (!$eventTag) {
                throw new NotFoundException(__('Invalid tag.'));
            }

            $this->set('is_local', $eventTag['EventTag']['local']);
            $this->set('tag', $eventTag);
            $this->set('id', $event['Event']['id']);
            $this->set('tag_id', $tag_id);
            $this->set('model', 'Event');
            $this->set('model_name', $event['Event']['info']);
            $this->render('/Attributes/ajax/tagRemoveConfirmation');
        } else {
            $rearrangeRules = array(
                'request' => false,
                'Event' => false,
                'tag_id' => 'tag',
                'event_id' => 'event',
                'id' => 'event'
            );
            $RearrangeTool = new RequestRearrangeTool();
            $this->request->data = $RearrangeTool->rearrangeArray($this->request->data, $rearrangeRules);
            if ($id === false) {
                $id = $this->request->data['event'];
            }
            if ($tag_id === false) {
                $tag_id = $this->request->data['tag'];
            }
            if (empty($tag_id)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid ' . ($galaxy ? 'Galaxy' : 'Tag') . '.')), 'status'=>200, 'type' => 'json'));
            }
            if (!is_numeric($tag_id)) {
                $tag = $this->Event->EventTag->Tag->find('first', array('recursive' => -1, 'conditions' => array('LOWER(Tag.name) LIKE' => strtolower(trim($tag_id)))));
                if (empty($tag)) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid ' . ($galaxy ? 'Galaxy' : 'Tag') . '.')), 'status'=>200, 'type' => 'json'));
                }
                $tag_id = $tag['Tag']['id'];
            }
            if (!is_numeric($id)) {
                $id = $this->request->data['Event']['id'];
            }
            $this->Event->recursive = -1;
            $event = $this->Event->read(array(), $id);
            $eventTag = $this->Event->EventTag->find('first', array(
                'conditions' => array(
                    'event_id' => $id,
                    'tag_id' => $tag_id
                ),
                'recursive' => -1,
            ));
            if (!$eventTag) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid event - ' . ($galaxy ? 'galaxy' : 'tag') . ' combination.')), 'status'=>200, 'type' => 'json'));
            }
            // org should allow to (un)tag too, so that an event that gets pushed can be (un)tagged locally by the owning org
            if (!$this->__canModifyTag($event, $eventTag['EventTag']['local'])) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
            }
            $this->Event->insertLock($this->Auth->user(), $id);
            $tag = $this->Event->EventTag->Tag->find('first', array(
                'conditions' => array('Tag.id' => $tag_id),
                'recursive' => -1,
                'fields' => array('Tag.name')
            ));
            if ($this->Event->EventTag->delete($eventTag['EventTag']['id'])) {
                if (empty($eventTag['EventTag']['local'])) {
                    $this->Event->unpublishEvent($event);
                }
                $log = ClassRegistry::init('Log');
                $log->createLogEntry($this->Auth->user(), 'tag', 'Event', $id, 'Removed tag (' . $tag_id . ') "' . $tag['Tag']['name'] . '" from event (' . $id . ')', 'Event (' . $id . ') untagged of Tag (' . $tag_id . ')');
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => ($galaxy ? 'Galaxy' : 'Tag') . ' removed.', 'check_publish' => empty($eventTag['EventTag']['local']))), 'status'=>200, 'type' => 'json'));
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => ($galaxy ? 'Galaxy' : 'Tag') . ' could not be removed.')), 'status'=>200, 'type' => 'json'));
            }
        }
    }

    /*
     * adhereToWarninglists is used when querying this function via the API
     * possible options:
     *  - false: (default) ignore warninglists
     *  - 'soft': Unset the IDS flag of all attributes hitting on a warninglist item
     *  - true / 'hard': Block attributes from being added that have a hit in the warninglists
     * returnMetaAttributes is a flag that will force the API to return the results of the
     * parsing directly for external further processing. The flag is a simple boolean flag (0||1)
     */
    public function freeTextImport($id, $adhereToWarninglists = false, $returnMetaAttributes = false)
    {
        $this->request->allowMethod(['post', 'get']);

        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        $this->set('event_id', $event['Event']['id']);
        if ($this->request->is('get')) {
            $this->layout = false;
            $this->request->data['MispAttribute']['event_id'] = $event['Event']['id'];

        } else if ($this->request->is('post')) {
            App::uses('ComplexTypeTool', 'Tools');
            $complexTypeTool = new ComplexTypeTool();
            $this->loadModel('Warninglist');
            $complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
            $complexTypeTool->setSecurityVendorDomains($this->Warninglist->fetchSecurityVendorDomains());
            if (!isset($this->request->data['Attribute'])) {
                $this->request->data = array('Attribute' => $this->request->data);
            }
            if (!isset($this->request->data['Attribute']['value'])) {
                $this->request->data['Attribute'] = array('value' => $this->request->data['Attribute']);
            }
            if (isset($this->request->data['Attribute']['adhereToWarninglists'])) {
                $adhereToWarninglists = $this->request->data['Attribute']['adhereToWarninglists'];
            }
            $resultArray = $complexTypeTool->checkFreeText($this->request->data['Attribute']['value']);
            foreach ($resultArray as &$attribute) {
                $attribute['to_ids'] = $this->Event->Attribute->typeDefinitions[$attribute['default_type']]['to_ids'];
            }
            if ($this->_isRest()) {
                // Keep this 'types' format for rest response, but it is not necessary for UI
                foreach ($resultArray as $key => $r) {
                    $temp = array();
                    foreach ($r['types'] as $type) {
                        $temp[$type] = $type;
                    }
                    $resultArray[$key]['types'] = $temp;
                }
                if ($returnMetaAttributes || !empty($this->request->data['Attribute']['returnMetaAttributes'])) {
                    return $this->RestResponse->viewData($resultArray, $this->response->type());
                } else {
                    return $this->__pushFreetext(
                        $resultArray,
                        $event,
                        isset($this->request->data['Attribute']['distribution']) ? $this->request->data['Attribute']['distribution'] : false,
                        isset($this->request->data['Attribute']['sharing_group_id']) ? $this->request->data['Attribute']['sharing_group_id'] : false,
                        $adhereToWarninglists
                    );
                }
            }
            $this->Event->Attribute->fetchRelated($this->Auth->user(), $resultArray);
            $typeCategoryMapping = [
                'ip-src/ip-dst' => [
                    'Network activity' => 'Network activity',
                    'Payload delivery' => 'Payload delivery',
                    'External analysis' => 'External analysis'
                ],
            ];
            foreach ($this->Event->Attribute->categoryDefinitions as $k => $cat) {
                foreach ($cat['types'] as $type) {
                    $typeCategoryMapping[$type][$k] = $k;
                }
            }
            $distributions = $this->Event->Attribute->distributionLevels;
            $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
            if (empty($sgs)) {
                unset($distributions[4]);
            }

            $this->set('proposals', !$this->__canModifyEvent($event));
            $this->set('distributions', $distributions);
            $this->set('sgs', $sgs);
            $this->set('event', $event);
            $this->set('mayModify', $this->__canModifyEvent($event));
            $this->set('typeDefinitions', $this->Event->Attribute->typeDefinitions);
            $this->set('typeCategoryMapping', $typeCategoryMapping);
            $this->set('defaultAttributeDistribution', $this->Event->Attribute->defaultDistribution());
            $this->set('resultArray', $resultArray);
            $this->set('importComment', '');
            $this->set('title_for_layout', __('Freetext Import Results'));
            $this->set('title', __('Freetext Import Results'));
            $this->set('missingTldLists', $this->Warninglist->missingTldLists());
            $this->render('resolved_attributes');
        }
    }

    private function __pushFreetext($attributes, array $event, $distribution = false, $sg = false, $adhereToWarninglists = false)
    {
        if ($distribution === false) {
            if (Configure::read('MISP.default_attribute_distribution') != null) {
                $distribution = $this->Event->Attribute->defaultDistribution();
            } else {
                $distribution = 0;
            }
        }
        // prepare the default choices
        foreach ($attributes as $k => $attribute) {
            $attribute['type'] = $attribute['default_type'];
            unset($attribute['default_type']);
            unset($attribute['types']);
            if (isset($attribute['default_category'])) {
                $attribute['category'] = $attribute['default_category'];
                unset($attribute['default_category']);
            } else {
                $attribute['category'] = $this->Event->Attribute->typeDefinitions[$attribute['type']]['default_category'];
            }
            $attribute['distribution'] = $distribution;
            $attribute['event_id'] = $event['Event']['id'];
            $attributes[$k] = $attribute;
        }
        // actually save the attribute now
        $proposals = !$this->__canModifyEvent($event);
        $temp = $this->Event->processFreeTextDataRouter($this->Auth->user(), $attributes, $event['Event']['id'], '', $proposals, $adhereToWarninglists, empty(Configure::read('MISP.background_jobs')));
        if (empty(Configure::read('MISP.background_jobs'))) {
            $attributes = $temp;
        }
        // FIXME $attributes does not contain the onteflyattributes
        $attributes = array_values($attributes);
        return $this->RestResponse->viewData($attributes, $this->response->type());
    }

    public function saveFreeText($id)
    {
        $this->request->allowMethod(['post']);
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (!$event) {
            throw new NotFoundException(__('Invalid event.'));
        }

        $this->Event->insertLock($this->Auth->user(), $id);
        $this->request->data['Attribute'] = $this->request->data['MispAttribute'];
        unset($this->request->data['MispAttribute']);
        $attributes = $this->_jsonDecode($this->request->data['Attribute']['JsonObject']);
        $defaultComment = $this->request->data['Attribute']['default_comment'];
        $proposals = !$this->__canModifyEvent($event) || (isset($this->request->data['Attribute']['force']) && $this->request->data['Attribute']['force']);
        $flashMessage = $this->Event->processFreeTextDataRouter($this->Auth->user(), $attributes, $id, $defaultComment, $proposals);
        $this->Flash->info($flashMessage);

        if ($this->request->is('ajax')) {
            return $this->RestResponse->viewData($flashMessage, $this->response->type());
        } else {
            $this->redirect(array('controller' => 'events', 'action' => 'view', $id));
        }
    }

    public function stix2()
    {
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'key', 'id', 'withAttachment', 'tags', 'from', 'to', 'last'
            ),
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => func_get_args(),
            'injectedParams' => array(
                'returnFormat' => 'stix2'
            ),
            'alias' => array(
                'id' => 'eventid'
            )
        ));
        return $this->restSearch();
    }

    public function stix()
    {
        $this->_legacyAPIRemap(array(
            'paramArray' => array(
                'key', 'id', 'withAttachment', 'tags', 'from', 'to', 'last'
            ),
            'request' => $this->request,
            'named_params' => $this->params['named'],
            'ordered_url_params' => func_get_args(),
            'injectedParams' => array(
                'returnFormat' => 'stix'
            ),
            'alias' => array(
                'id' => 'eventid'
            )
        ));
        return $this->restSearch();
    }

    public function filterEventIdsForPush()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint requires a POST request.'));
        }

        $incomingUuids = [];
        $incomingEvents = [];
        foreach ($this->request->data as $event) {
            $incomingUuids[] = $event['Event']['uuid'];
            $incomingEvents[$event['Event']['uuid']] = $event['Event']['timestamp'];
        }
        $events = $this->Event->find('all', [
            'conditions' => ['Event.uuid' => $incomingUuids],
            'recursive' => -1,
            'fields' => ['Event.uuid', 'Event.timestamp', 'Event.locked'],
        ]);
        foreach ($events as $event) {
            if ($event['Event']['timestamp'] >= $incomingEvents[$event['Event']['uuid']]) {
                unset($incomingEvents[$event['Event']['uuid']]);
                continue;
            }
            if ($event['Event']['locked'] == 0) {
                unset($incomingEvents[$event['Event']['uuid']]);
            }
        }
        return $this->RestResponse->viewData(array_keys($incomingEvents), $this->response->type());
    }

    public function checkuuid($uuid)
    {
        if (!$this->userRole['perm_sync']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        $events = $this->Event->find('first', array(
                'conditions' => array('Event.uuid' => $uuid),
                'recursive' => -1,
                'fields' => array('Event.uuid'),
        ));
        $this->set('result', array('result' => empty($events)));
    }

    public function pushProposals($uuid)
    {
        $message= "";
        $success = true;
        $counter = 0;
        if (!$this->userRole['perm_sync'] || !$this->userRole['perm_add']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if ($this->request->is('post')) {
            $event = $this->Event->find('first', array(
                    'conditions' => array('Event.uuid' => $uuid),
                    'contains' => array('ShadowAttribute', 'Attribute' => array(
                        'fields' => array('id', 'uuid', 'event_id'),
                    )),
                    'fields' => array('Event.uuid', 'Event.id'),
            ));
            if (empty($event)) {
                $message = "Event not found.";
                $success = false;
            } else {
                foreach ($this->request->data as $k => $sa) {
                    if (isset($event['ShadowAttribute'])) {
                        foreach ($event['ShadowAttribute'] as $oldk => $oldsa) {
                            if ($sa['event_uuid'] == $oldsa['event_uuid'] && $sa['value'] == $oldsa['value'] && $sa['type'] == $oldsa['type'] && $sa['category'] == $oldsa['category'] && $sa['to_ids'] == $oldsa['to_ids']) {
                                if ($oldsa['timestamp'] < $sa['timestamp']) {
                                    $this->Event->ShadowAttribute->delete($oldsa['id']);
                                } else {
                                    continue 2;
                                }
                            }
                        }
                    }
                    $sa['event_id'] = $event['Event']['id'];
                    if ($sa['old_id'] != 0) {
                        foreach ($event['Attribute'] as $attribute) {
                            if ($sa['uuid'] == $attribute['uuid']) {
                                $sa['old_id'] = $attribute['id'];
                            }
                        }
                    }
                    if (isset($sa['id'])) {
                        unset($sa['id']);
                    }
                    $this->Event->ShadowAttribute->create();
                    if (!$this->Event->ShadowAttribute->save(array('ShadowAttribute' => $sa))) {
                        $message = "Some of the proposals could not be saved.";
                        $success = false;
                    } else {
                        $counter++;
                    }
                    if (!$sa['deleted']) {
                        $this->Event->ShadowAttribute->sendProposalAlertEmail($event['Event']['id']);
                    }
                }
            }
            if ($success) {
                if ($counter) {
                    $message = $counter . " Proposal(s) added.";
                } else {
                    $message = "Nothing to update.";
                }
            }
            $this->set('data', array('success' => $success, 'message' => $message, 'counter' => $counter));
            $this->set('_serialize', 'data');
        }
    }

    public function exportChoice($id)
    {
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
        }
        $id = $event['Event']['id'];
        $exports = array(
            'json' => array(
                'url' => $this->baseurl . '/events/restSearch/json/includeAnalystData:1/eventid:' . $id . '.json',
                'text' => __('MISP JSON (metadata + all attributes)'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/json/withAttachments:1/includeAnalystData:1/eventid:' . $id . '.json',
                'checkbox_default' => true,
            ),
            'xml' => array(
                'url' => $this->baseurl . '/events/restSearch/xml/eventid:' . $id . '.xml',
                'text' => __('MISP XML (metadata + all attributes)'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/xml/eventid:' . $id . '/withAttachments:1.xml',
                'checkbox_default' => true,
            ),
            'openIOC' => array(
                'url' => $this->baseurl . '/events/restSearch/openioc/to_ids:1/published:1/eventid:' . $id . '.json',
                'text' => __('OpenIOC (all indicators marked to IDS)'),
                'requiresPublished' => false,
                'checkbox' => false,
            ),
            'csv' => array(
                'url' => $this->baseurl . '/events/restSearch/returnFormat:csv/to_ids:1/published:1/includeContext:0/eventid:' . $id,
                'text' => 'CSV',
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Include non-IDS marked attributes'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/returnFormat:csv/to_ids:1||0/published:1||0/includeContext:0/eventid:' . $id,
            ),
            'csv_with_context' => array(
                'url' => $this->baseurl . '/events/restSearch/returnFormat:csv/to_ids:1/published:1/includeContext:1/eventid:' . $id,
                'text' => __('CSV with additional context'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Include non-IDS marked attributes'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/returnFormat:csv/to_ids:1||0/published:1||0/includeContext:1/eventid:' . $id,
            ),
            'stix_xml' => array(
                'url' => $this->baseurl . '/events/restSearch/stix/eventid:' . $id,
                'text' => __('STIX 1 XML (metadata + all attributes)'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/stix/eventid:' . $id . '/withAttachments:1',
            ),
            'stix_json' => array(
                'url' => $this->baseurl . '/events/restSearch/stix-json/eventid:' . $id,
                'text' => __('STIX 1 JSON (metadata + all attributes)'),
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/stix-json/withAttachments:1/eventid:' . $id,
            ),
            'stix2_json' => array(
                'url' => $this->baseurl . '/events/restSearch/stix2/eventid:' . $id,
                'text' => 'STIX 2',
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Encode Attachments'),
                'checkbox_set' => $this->baseurl . '/events/restSearch/stix2/eventid:' . $id . '/withAttachments:1',
            ),
            'rpz' => array(
                'url' => $this->baseurl . '/attributes/restSearch/returnFormat:rpz/published:1||0/eventid:' . $id,
                'text' => __('RPZ Zone file'),
                'requiresPublished' => false,
                'checkbox' => false,
            ),
            'suricata' => array(
                'url' => $this->baseurl . '/events/restSearch/returnFormat:suricata/published:1||0/eventid:' . $id,
                'text' => __('Suricata rules'),
                'requiresPublished' => false,
                'checkbox' => false,
            ),
            'snort' => array(
                'url' => $this->baseurl . '/events/restSearch/returnFormat:snort/published:1||0/eventid:' . $id,
                'text' => __('Snort rules'),
                'requiresPublished' => false,
                'checkbox' => false,
            ),
            'bro' => array(
                'url' => $this->baseurl . '/attributes/bro/download/all/false/' . $id,
                // 'url' => $this->baseurl . '/attributes/restSearch/returnFormat:bro/published:1||0/eventid:' . $id,
                'text' => __('Bro rules'),
                'requiresPublished' => false,
                'checkbox' => false,
            ),
            'text' => array(
                'text' => __('Export all attribute values as a text file'),
                'url' => $this->baseurl . '/attributes/restSearch/returnFormat:text/published:1||0/eventid:' . $id,
                'requiresPublished' => false,
                'checkbox' => true,
                'checkbox_text' => __('Include non-IDS marked attributes'),
                'checkbox_set' => $this->baseurl . '/attributes/restSearch/returnFormat:text/published:1||0/to_ids:1||0/eventid:' . $id,
            ),
        );
        if ($event['Event']['published'] == 0) {
            foreach ($exports as $k => $export) {
                if ($export['requiresPublished']) {
                    unset($exports[$k]);
                }
            }
            $exports['csv'] = array(
                'url' => $this->baseurl . '/events/restSearch/returnFormat:csv/includeContext:0/eventid:' . $id,
                'text' => __('CSV (event not published, IDS flag ignored)'),
                'requiresPublished' => false,
                'checkbox' => false,
            );
        }
        $this->loadModel('Module');
        $modules = $this->Module->getEnabledModules($this->Auth->user(), false, 'Export');
        if (is_array($modules) && !empty($modules)) {
            foreach ($modules['modules'] as $module) {
                $exports[$module['name']] = array(
                    'url' => $this->baseurl . '/events/exportModule/' . $module['name'] . '/' . $id,
                    'text' => Inflector::humanize($module['name']),
                    'requiresPublished' => true,
                    'checkbox' => false,
                );
            }
        }
        $this->set('exports', $exports);
        $this->set('id', $id);
        $this->render('ajax/exportChoice');
    }

    public function importChoice($id = false, $scope = 'event')
    {
        if ($scope === 'event') {
            $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
            if (empty($event)) {
                throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
            }
            $imports = array(
                'MISP JSON' => array(
                    'url' => $this->baseurl . '/events/populate/'.$id,
                    'text' => __('Populate using a JSON file containing MISP event content data'),
                    'ajax' => false
                ),
                'freetext' => array(
                    'url' => $this->baseurl . '/events/freeTextImport/' . $id,
                    'text' => __('Freetext Import'),
                    'ajax' => true,
                    'target' => 'popover_form'
                ),
                'template' => array(
                    'url' => $this->baseurl . '/templates/templateChoices/' . $id,
                    'text' => __('Populate using a Template'),
                    'ajax' => true,
                    'target' => 'popover_form'
                ),
                'OpenIOC' => array(
                    'url' => $this->baseurl . '/events/addIOC/' . $id,
                    'text' => __('OpenIOC Import'),
                    'ajax' => false,
                ),
                'ThreatConnect' => array(
                    'url' => $this->baseurl . '/attributes/add_threatconnect/' . $id,
                    'text' => __('ThreatConnect Import'),
                    'ajax' => false
                ),
                'Forensic analysis' => array(
                    'url' => $this->baseurl . '/events/upload_analysis_file/'.$id,
                    'text' => __('(Experimental) Forensic analysis - Mactime'),
                    'ajax' => false,
                )
            );
            $this->loadModel('Module');
            $modules = $this->Module->getEnabledModules($this->Auth->user(), false, 'Import');
            if (is_array($modules) && !empty($modules)) {
                foreach ($modules['modules'] as $module) {
                    $imports[$module['name']] = array(
                        'url' => $this->baseurl . '/events/importModule/' . $module['name'] . '/' . $id,
                        'text' => Inflector::humanize($module['name']),
                        'ajax' => false,
                    );
                }
            }
        } else {
            $imports = array(
                'MISP' => array(
                    'url' => $this->baseurl . '/events/add_misp_export',
                    'text' => __('MISP standard (recommended exchange format - lossless)'),
                    'ajax' => false,
                    'bold' => true,
                ),
                'STIX' => array(
                    'url' => $this->baseurl . '/events/upload_stix',
                    'text' => __('STIX 1.x format (lossy)'),
                    'ajax' => false,
                ),
                'STIX2' => array(
                    'url' => $this->baseurl . '/events/upload_stix/2',
                    'text' => __('STIX 2.x format (lossy)'),
                    'ajax' => false,
                )
            );
        }
        $this->set('imports', $imports);
        $this->set('id', $id);
        $this->render('ajax/importChoice');
    }

    // API for pushing samples to MISP
    // Either send it to an existing event, or let MISP create a new one automatically
    public function upload_sample($event_id = null, $advanced = false)
    {
        $this->loadModel('Log');
        $hashes = array('md5' => 'malware-sample', 'sha1' => 'filename|sha1', 'sha256' => 'filename|sha256');
        $categoryDefinitions = $this->Event->Attribute->categoryDefinitions;
        $categories = array();
        foreach ($categoryDefinitions as $k => $v) {
            if (in_array('malware-sample', $v['types']) && !in_array($k, $categories)) {
                $categories[] = $k;
            }
        }
        $default_distribution = !empty(Configure::read('MISP.default_attribute_distribution')) ? Configure::read('MISP.default_attribute_distribution') : 5;
        if ($default_distribution == 'event') {
            $default_distribution = 5;
        }
        // #TODO i18n
        $parameter_options = array(
                'distribution' => array('valid_options' => array(0, 1, 2, 3, 5), 'default' => $default_distribution),
                'threat_level_id' => array('valid_options' => array(1, 2, 3, 4), 'default' => 4),
                'analysis' => array('valid_options' => array(0, 1, 2), 'default' => 0),
                'info' => array('default' =>  'Malware samples uploaded on ' . date('Y-m-d')),
                'to_ids' => array('valid_options' => array(0, 1), 'default' => 1),
                'category' => array('valid_options' => $categories, 'default' => 'Payload installation'),
                'comment' => array('default' => '')
        );

        if (!$this->userRole['perm_auth']) {
            throw new MethodNotAllowedException(__('This functionality requires API key access.'));
        }
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('Please POST the samples as described on the automation page.'));
        }
        if ($this->response->type() === 'application/json') {
            $data = $this->request->input('json_decode', true);
        } elseif ($this->response->type() === 'application/xml') {
            $data = $this->request->data;
        } else {
            throw new BadRequestException(__('Please POST the samples as described on the automation page.'));
        }

        if (isset($data['request'])) {
            $data = $data['request'];
        }
        foreach ($parameter_options as $k => $v) {
            if (isset($data[$k])) {
                if (isset($v['valid_options']) && !in_array($data[$k], $v['valid_options'])) {
                    $data['settings'][$k] = $v['default'];
                } else {
                    $data['settings'][$k] = $data[$k];
                }
                unset($data[$k]);
            } else {
                $data['settings'][$k] = $v['default'];
            }
        }
        if (isset($data['files'])) {
            foreach ($data['files'] as $k => $file) {
                if (!isset($file['filename']) || !isset($file['data'])) {
                    unset($data['files'][$k]);
                } else {
                    $data['files'][$k]['md5'] = md5(base64_decode($file['data']));
                }
            }
        }

        if (empty($data['files'])) {
            throw new BadRequestException(__('No samples received, or samples not in the correct format. Please refer to the API documentation on the automation page.'));
        }
        if (isset($event_id)) {
            $data['settings']['event_id'] = $event_id;
        }
        if (isset($data['settings']['event_id'])) {
            $this->Event->id = $data['settings']['event_id'];
            if (!$this->Event->exists()) {
                throw new NotFoundException(__('Event not found'));
            }
        }
        if (isset($data['advanced'])) {
            $advanced = $data['advanced'];
        }

        // check if the user has permission to create attributes for an event, if the event ID has been passed
        // If not, create an event
        if (isset($data['settings']['event_id']) && !empty($data['settings']['event_id']) && is_numeric($data['settings']['event_id'])) {
            $conditions = array('Event.id' => $data['settings']['event_id']);
            if (!$this->_isSiteAdmin()) {
                $conditions[] = array('Event.orgc_id' => $this->Auth->user('org_id'));
                if (!$this->userRole['perm_modify_org']) {
                    $conditions[] = array('Event.user_id' => $this->Auth->user('id'));
                }
            }
            $event = $this->Event->find('first', array(
                'recursive' => -1,
                'conditions' => $conditions,
                'fields' => array('id'),
            ));
            if (empty($event)) {
                throw new NotFoundException(__('Event not found.'));
            }
            $this->Event->insertLock($this->Auth->user(), $event['Event']['id']);
            $this->Event->id = $data['settings']['event_id'];
            $date = new DateTime();
            $this->Event->saveField('timestamp', $date->getTimestamp());
            $this->Event->saveField('published', 0);
        } else {
            $this->Event->create();
            if ($data['settings']['distribution'] == 5) {
                throw new BadRequestException(__('Distribution level 5 is not supported when uploading a sample without passing an event ID. Distribution level 5 is meant to take on the distribution level of an existing event.'));
            }
            $result = $this->Event->save(
                array(
                    'info' => $data['settings']['info'],
                    'analysis' => $data['settings']['analysis'],
                    'threat_level_id' => $data['settings']['threat_level_id'],
                    'distribution' => $data['settings']['distribution'],
                    'date' => date('Y-m-d'),
                    'orgc_id' => $this->Auth->user('org_id'),
                    'org_id' => $this->Auth->user('org_id'),
                    'user_id' => $this->Auth->user('id'),
                )
            );
            if (!$result) {
                $this->Log->saveOrFailSilently(array(
                        'org' => $this->Auth->user('Organisation')['name'],
                        'model' => 'Event',
                        'model_id' => 0,
                        'email' => $this->Auth->user('email'),
                        'action' => 'upload_sample',
                        'user_id' => $this->Auth->user('id'),
                        'title' => 'Error: Failed to create event using the upload sample functionality',
                        'change' => 'There was an issue creating an event (' . $data['settings']['info'] . '). The validation errors were: ' . json_encode($this->Event->validationErrors),
                ));
                throw new BadRequestException(__('The creation of a new event with the supplied information has failed.'));
            }
            $data['settings']['event_id'] = $this->Event->id;
            $event_id = $this->Event->id;
        }

        if (!isset($data['settings']['to_ids']) || !in_array($data['settings']['to_ids'], array('0', '1', 0, 1))) {
            $data['settings']['to_ids'] = 1;
        }
        $successCount = 0;
        $errors = array();
        App::uses('FileAccessTool', 'Tools');
        foreach ($data['files'] as $file) {
            $tmpdir = Configure::read('MISP.tmpdir') ? Configure::read('MISP.tmpdir') : APP . 'tmp';
            $tmpfile = FileAccessTool::createTempFile($tmpdir, $prefix = 'MISP_upload');
            FileAccessTool::writeToFile($tmpfile, base64_decode($file['data']));
            $tmpfile = new File($tmpfile);
            if ($advanced) {
                $result = $this->Event->Attribute->advancedAddMalwareSample(
                    $event_id,
                    $data['settings'],
                    $file['filename'],
                    $tmpfile
                );
                if ($result) {
                    $successCount++;
                } else {
                    $errors[] = $file['filename'];
                }
            } else {
                $result = $this->Event->Attribute->simpleAddMalwareSample(
                    $event_id,
                    $data['settings'],
                    $file['filename'],
                    $tmpfile
                );
                if ($result) {
                    $successCount++;
                } else {
                    $errors[] = $file['filename'];
                }
            }
            if (!empty($result)) {
                foreach ($result['Object'] as $object) {
                    if (isset($data['settings']['distribution'])) {
                        $object['distribution'] = $data['settings']['distribution'];
                    }
                    $object['sharing_group_id'] = isset($data['settings']['sharing_group_id']) ? $data['settings']['sharing_group_id'] : 0;
                    if (!empty($object['Attribute'])) {
                        foreach ($object['Attribute'] as $k => $attribute) {
                            if ($attribute['value'] == $tmpfile->name) {
                                $object['Attribute'][$k]['value'] = $file['filename'];
                            }
                            if (isset($data['settings']['distribution'])) {
                                $object['Attribute'][$k]['distribution'] = $data['settings']['distribution'];
                            }
                            $object['Attribute'][$k]['sharing_group_id'] = isset($data['settings']['sharing_group_id']) ? $data['settings']['sharing_group_id'] : 0;
                        }
                    }
                    $this->loadModel('MispObject');
                    $this->MispObject->captureObject(array('Object' => $object), $event_id, $this->Auth->user());
                }
                if (!empty($result['ObjectReference'])) {
                    foreach ($result['ObjectReference'] as $reference) {
                        $this->MispObject->ObjectReference->smartSave($reference, $event_id);
                    }
                }
            }
            FileAccessTool::deleteFile($tmpfile->path);
        }
        if (!empty($errors)) {
            $this->set('errors', $errors);
            if ($successCount > 0) {
                $this->set('name', 'Partial success');
                $this->set('message', 'Successfuly saved ' . $successCount . ' sample(s), but some samples could not be saved.');
                $this->set('url', $this->baseurl . '/events/view/' . $data['settings']['event_id']);
                $this->set('id', $data['settings']['event_id']);
                $this->set('_serialize', array('name', 'message', 'url', 'id', 'errors'));
            } else {
                $this->set('name', 'Failed');
                $this->set('message', 'Failed to save any of the supplied samples.');
                $this->set('_serialize', array('name', 'message', 'errors'));
            }
        } else {
            $this->set('name', 'Success');
            $this->set('message', 'Success, saved all attributes.');
            $this->set('url', $this->baseurl . '/events/view/' . $data['settings']['event_id']);
            $this->set('id', $data['settings']['event_id']);
            $this->set('_serialize', array('name', 'message', 'url', 'id'));
        }
        $this->view($data['settings']['event_id']);
        $this->render('view');
    }

    public function viewGraph($id)
    {
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event.'));
        }

        $this->set('event', $event);
        $this->set('scope', 'event');
        $this->set('mayModify', $this->__canModifyEvent($event));
        $this->set('mayPublish', $this->__canPublishEvent($event));
        $this->set('id', $event['Event']['id']);
    }

    /*
        public function deleteNode($id) {
            if (!$this->request->is('post')) throw new MethodNotAllowedException(__('Only POST requests are allowed.'));
            App::uses('CorrelationGraphTool', 'Tools');
            $grapher = new CorrelationGraphTool();
            $grapher->construct($this->Event, $this->Taxonomy, $this->GalaxyCluster, $this->Auth->user(), $this->request->data);
            $json = $grapher->deleteNode($id);
        }
    */

    public function updateGraph($id, $type = 'event')
    {
        $user = $this->_closeSession();

        $validTools = array('event', 'galaxy', 'tag');
        if (!in_array($type, $validTools, true)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }

        $this->loadModel('Taxonomy');
        $this->loadModel('GalaxyCluster');
        App::uses('CorrelationGraphTool', 'Tools');

        $data = $this->request->is('post') ? $this->request->data : array();
        $grapher = new CorrelationGraphTool($this->Event, $this->Taxonomy, $this->GalaxyCluster, $user, $data);
        $json = $grapher->buildGraphJson($id, $type);
        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $this->RestResponse->viewData($json, 'json');
    }

    private function __genDistributionGraph($id, $type = 'event', $extended = 0, $user = null)
    {
        $validTools = array('event');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }

        $this->loadModel('Server');
        $servers = $this->Server->find('column', array(
            'fields' => array('Server.name'),
        ));

        App::uses('DistributionGraphTool', 'Tools');
        $user = $user ?: $this->Auth->user();
        $grapher = new DistributionGraphTool($this->Event, $servers, $user, $extended);
        $json = $grapher->get_distributions_graph($id);

        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $json;
    }

    public function getEventTimeline($id, $type = 'event')
    {
        $validTools = array('event');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException('Invalid type.');
        }
        App::uses('EventTimelineTool', 'Tools');
        $grapher = new EventTimelineTool();
        $data = $this->request->is('post') ? $this->request->data : array();
        $dataFiltering = array_key_exists('filtering', $data) ? $data['filtering'] : array();
        $scope = isset($data['scope']) ? $data['scope'] : 'seen';

        $extended = isset($this->params['named']['extended']) ? 1 : 0;

        $grapher->construct($this->Event, $this->Auth->user(), $dataFiltering, $extended);
        if ($scope == 'seen') {
            $json = $grapher->get_timeline($id);
        } elseif ($scope == 'sightings') {
            $json = $grapher->get_sighting_timeline($id);
        }

        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getDistributionGraph($id, $type = 'event')
    {
        $user = $this->_closeSession();
        $extended = isset($this->params['named']['extended']) ? 1 : 0;
        $json = $this->__genDistributionGraph($id, $type, $extended, $user);
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getEventGraphReferences($id, $type = 'event')
    {
        $validTools = array('event');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $this->loadModel('Tag');
        App::uses('EventGraphTool', 'Tools');
        $grapher = new EventGraphTool();
        $data = $this->request->is('post') ? $this->request->data : array();

        $extended = isset($this->params['named']['extended']) ? 1 : 0;

        $grapher->construct($this->Event, $this->Tag, $this->Auth->user(), $data['filtering'], $extended);
        $json = $grapher->get_references($id);

        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getEventGraphTags($id, $type = 'event')
    {
        $validTools = array('event');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $this->loadModel('Tag');
        App::uses('EventGraphTool', 'Tools');
        $grapher = new EventGraphTool();
        $data = $this->request->is('post') ? $this->request->data : array();

        $extended = isset($this->params['named']['extended']) ? 1 : 0;

        $grapher->construct($this->Event, $this->Tag, $this->Auth->user(), $data['filtering'], $extended);
        $json = $grapher->get_tags($id);

        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getEventGraphGeneric($id, $type = 'event')
    {
        $validTools = array('event');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $this->loadModel('Tag');
        App::uses('EventGraphTool', 'Tools');
        $grapher = new EventGraphTool();
        $data = $this->request->is('post') ? $this->request->data : array();

        $extended = isset($this->params['named']['extended']) ? 1 : 0;

        $grapher->construct($this->Event, $this->Tag, $this->Auth->user(), $data['filtering'], $extended);
        if (!array_key_exists('keyType', $data)) {
            $keyType = ''; // empty key
        } else {
            $keyType = $data['keyType'];
        }
        $json = $grapher->get_generic_from_key($id, $keyType);

        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getReferenceData($uuid, $type = 'reference')
    {
        $validTools = array('reference');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        App::uses('EventGraphTool', 'Tools');
        $grapher = new EventGraphTool();
        $data = $this->request->is('post') ? $this->request->data : array();
        $grapher->construct_for_ref($this->Event->Object, $this->Auth->user());
        $json = $grapher->get_reference_data($uuid);

        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $this->RestResponse->viewData($json, 'json');
    }

    public function getObjectTemplate($type = 'templates')
    {
        $validTools = array('templates');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        App::uses('EventGraphTool', 'Tools');
        $eventGraphTool = new EventGraphTool();

        $data = $this->request->is('post') ? $this->request->data : array();
        $eventGraphTool->construct_for_ref($this->Event->Object, $this->Auth->user());
        $json = $eventGraphTool->get_object_templates();

        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $this->RestResponse->viewData($json, 'json');
    }

    public function viewGalaxyMatrix($scope_id, $galaxy_id, $scope='event', $disable_picking=false, $extended=false)
    {
        $this->loadModel('Galaxy');
        $mitreAttackGalaxyId = $this->Galaxy->getMitreAttackGalaxyId();
        if ($galaxy_id === 'mitre-attack') { // specific case for MITRE ATTACK matrix
            $galaxy_id = $mitreAttackGalaxyId;
        }

        $matrixData = $this->Galaxy->getMatrix($galaxy_id); // throws exception if matrix not found

        $local = !empty($this->params['named']['local']);
        $this->set('local', $local);

        $tabs = $matrixData['tabs'];
        $matrixTags = $matrixData['matrixTags'];
        $killChainOrders = $matrixData['killChain'];
        $instanceUUID = $matrixData['instance-uuid'];

        if ($scope == 'event') {
            $eventId = $scope_id;
        } elseif ($scope == 'attribute') {
            if ($scope_id == 'selected') {
                if (empty($this->params['named']['eventid'])) {
                    throw new Exception("Invalid Event.");
                }
                $eventId = $this->params['named']['eventid'];
            } else {
                $attribute = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array(
                    'conditions' => array('Attribute.id' => $scope_id),
                    'fields' => array('event_id'),
                    'flatten' => 1,
                ));
                if (empty($attribute)) {
                    throw new Exception("Invalid Attribute.");
                }
                $attribute = $attribute[0];
                $eventId = $attribute['Attribute']['event_id'];
            }
        } elseif ($scope == 'tag_collection') {
            $eventId = 0; // no event_id for tag_collection, consider all events
        } else {
            throw new Exception("Invalid options.");
        }

        if ($scope !== 'tag_collection') {
            $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $eventId, 'metadata' => true, 'extended' => $extended));
            if (empty($event)) {
                throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
            }
            if ($extended) {
                $eventIds = array();
                $eventIds[] = $eventId;
                foreach ($event[0]['Event']['extensionEvents'] as $extensionEvent) {
                    $eventIds[] = $extensionEvent['id'];
                }
                $eventId = $eventIds;
            }
            $scoresDataAttr = $this->Event->Attribute->AttributeTag->getTagScores($this->Auth->user(), $eventId, $matrixTags);
            $scoresDataEvent = $this->Event->EventTag->getTagScores($eventId, $matrixTags);
            $maxScore = 0;
            $scoresData = array();
            foreach (array_keys($scoresDataAttr['scores'] + $scoresDataEvent['scores']) as $key) {
                $sum = (isset($scoresDataAttr['scores'][$key]) ? $scoresDataAttr['scores'][$key] : 0) + (isset($scoresDataEvent['scores'][$key]) ? $scoresDataEvent['scores'][$key] : 0);
                $scoresData[$key] = $sum;
                $maxScore = max($maxScore, $sum);
            }
            $scores = $scoresData;
        } else {
            $scores = $scoresData = array();
        }
        // FIXME: temporary fix: add the score of deprecated mitre galaxies to the new one (for the stats)
        if ($matrixData['galaxy']['id'] == $mitreAttackGalaxyId) {
            $mergedScore = array();
            foreach ($scoresData as $tag => $v) {
                $predicateValue = explode(':', $tag, 2)[1];
                $predicateValue = explode('=', $predicateValue, 2);
                $predicate = $predicateValue[0];
                $clusterValue = $predicateValue[1];
                $mappedTag = '';
                $mappingWithoutExternalId = array();
                if ($predicate == 'mitre-attack-pattern') {
                    $mappedTag = $tag;
                    $name = explode(" ", $tag);
                    $name = join(" ", array_slice($name, 0, -2)); // remove " - external_id"
                    $mappingWithoutExternalId[$name] = $tag;
                } else {
                    $name = explode(" ", $clusterValue);
                    $name = join(" ", array_slice($name, 0, -2)); // remove " - external_id"
                    if (isset($mappingWithoutExternalId[$name])) {
                        $mappedTag = $mappingWithoutExternalId[$name];
                    } else {
                        $adjustedTagName = $this->Galaxy->GalaxyCluster->find('list', array(
                            'group' => array('GalaxyCluster.id', 'GalaxyCluster.tag_name'),
                            'conditions' => array('GalaxyCluster.tag_name LIKE' => 'misp-galaxy:mitre-attack-pattern=' . $name . '% T%'),
                            'fields' => array('GalaxyCluster.tag_name')
                        ));
                        $adjustedTagName = array_values($adjustedTagName)[0];
                        $mappingWithoutExternalId[$name] = $adjustedTagName;
                        $mappedTag = $mappingWithoutExternalId[$name];
                    }
                }

                if (isset($mergedScore[$mappedTag])) {
                    $mergedScore[$mappedTag] += $v;
                } else {
                    $mergedScore[$mappedTag] = $v;
                }
            }
            $scores = $mergedScore;
            $maxScore = !empty($mergedScore) ? max(array_values($mergedScore)) : 0;
        }
        // end FIXME

        $this->Galaxy->sortMatrixByScore($tabs, $scores);
        if ($this->_isRest()) {
            $json = array('matrix' => $tabs, 'scores' => $scores, 'instance-uuid' => $instanceUUID);
            return $this->RestResponse->viewData($json, 'json');
        }

        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('Invalid method.'));
        }

        App::uses('ColourGradientTool', 'Tools');
        $gradientTool = new ColourGradientTool();
        $colours = $gradientTool->createGradientFromValues($scores);
        $this->set('eventId', $eventId);
        $this->set('target_type', $scope);
        $this->set('columnOrders', $killChainOrders);
        $this->set('tabs', $tabs);
        $this->set('scores', $scores);
        $this->set('maxScore', $maxScore);
        if (!empty($colours)) {
            $this->set('colours', $colours['mapping']);
            $this->set('interpolation', $colours['interpolation']);
        }
        $this->set('pickingMode', !$disable_picking);
        $this->set('target_id', $scope_id);
        if ($matrixData['galaxy']['id'] == $mitreAttackGalaxyId) {
            $this->set('defaultTabName', 'mitre-attack');
            $this->set('removeTrailling', 2);
        }

        $this->render('/Elements/view_galaxy_matrix');
    }

    // Displays all the cluster relations for the provided event
    public function viewClusterRelations($eventId)
    {
        $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $eventId, 'flatten' => true));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event.'));
        }
        $event = $event[0];
        $clusterIds = array();
        foreach ($event['Galaxy'] as $galaxy) {
            foreach ($galaxy['GalaxyCluster'] as $cluster) {
                $clusterIds[$cluster['id']] = $cluster['id'];
            }
        }
        foreach ($event['Attribute'] as $attribute) {
            foreach ($attribute['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $cluster) {
                    $clusterIds[$cluster['id']] = $cluster['id'];
                }
            }
        }
        $this->loadModel('GalaxyCluster');
        $clusters = $this->GalaxyCluster->fetchGalaxyClusters($this->Auth->user(), array('conditions' => array('GalaxyCluster.id' => $clusterIds)), $full=true);
        App::uses('ClusterRelationsGraphTool', 'Tools');
        $grapher = new ClusterRelationsGraphTool($this->Auth->user(), $this->GalaxyCluster);
        $relations = $grapher->getNetwork($clusters, $keepNotLinkedClusters=true, $includeReferencingRelation=true);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($relations, $this->response->type());
        }
        $this->set('relations', $relations);
        $this->set('distributionLevels', $this->Event->distributionLevels);
    }

    public function delegation_index()
    {
        $this->loadModel('EventDelegation');
        $delegatedEvents = $this->EventDelegation->find('list', array(
                'conditions' => array('EventDelegation.org_id' => $this->Auth->user('org_id')),
                'fields' => array('event_id')
        ));
        $this->Event->contain(array('User.email', 'EventTag' => array('Tag')));
        $tags = $this->Event->EventTag->Tag->find('all', array('recursive' => -1));
        $tagNames = array('None');
        foreach ($tags as $k => $v) {
            $tagNames[$v['Tag']['id']] = $v['Tag']['name'];
        }
        $this->set('tags', $tagNames);
        $this->paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => array(
                    'Event.timestamp' => 'DESC'
            ),
            'contain' => array(
                    'Org' => array('fields' => array('id', 'name')),
                    'Orgc' => array('fields' => array('id', 'name')),
                    'SharingGroup' => array('fields' => array('id', 'name')),
                    'ThreatLevel' => array('fields' => array('ThreatLevel.name'))

            ),
            'conditions' => array('Event.id' => $delegatedEvents),
        );

        $this->set('events', $this->paginate());
        $this->set('threatLevels', $this->Event->ThreatLevel->listThreatLevels());
        $this->set('eventDescriptions', $this->Event->fieldDescriptions);
        $this->set('analysisLevels', $this->Event->analysisLevels);
        $this->set('distributionLevels', $this->Event->distributionLevels);

        $shortDist = array(0 => 'Organisation', 1 => 'Community', 2 => 'Connected', 3 => 'All', 4 => ' sharing Group');
        $this->set('shortDist', $shortDist);
        $this->set('ajax', false);
        $this->set('simple', true);
        $this->Event->contain(array('User.email', 'EventTag' => array('Tag')));
        $tags = $this->Event->EventTag->Tag->find('all', array('recursive' => -1));
        $tagNames = array('None');
        foreach ($tags as $k => $v) {
            $tagNames[$v['Tag']['id']] = $v['Tag']['name'];
        }
        $this->set('tags', $tagNames);
        $this->render('index');
    }

    // expects a model ID, model type, the module to be used (optional) and the type of enrichment (optional)
    public function queryEnrichment($id, $module = false, $type = 'Enrichment', $model = 'Attribute')
    {
        if (!Configure::read('Plugin.' . $type . '_services_enable')) {
            throw new MethodNotAllowedException(__('%s services are not enabled.', $type));
        }

        if (!in_array($model, array('Attribute', 'ShadowAttribute', 'Object', 'Event'))) {
            throw new MethodNotAllowedException(__('Invalid model.'));
        }

        $this->loadModel('Module');
        $enabledModules = $this->Module->getEnabledModules($this->Auth->user(), false, $type);

        if (!is_array($enabledModules) || empty($enabledModules)) {
            throw new MethodNotAllowedException(__('No valid %s options found for this %s.', $type, strtolower($model)));
        }

        if ($model === 'Attribute' || $model === 'ShadowAttribute') {
            $attribute = $this->Event->Attribute->fetchAttributes($this->Auth->user(), [
                'conditions' => [
                    'Attribute.id' => $id
                ],
                'flatten' => 1,
                'includeEventTags' => 1,
                'contain' => ['Event' => ['fields' => ['distribution', 'sharing_group_id']]],
            ]);
            if (empty($attribute)) {
                throw new MethodNotAllowedException(__('Attribute not found or you are not authorised to see it.'));
            }
        }

        if ($model === 'Object') {
            $object = $this->Event->Object->fetchObjects($this->Auth->user(), [
                'conditions' => [
                    'Object.id' => $id
                ],
                'flatten' => 1,
                'includeEventTags' => 1,
                'contain' => ['Event' => ['fields' => ['distribution', 'sharing_group_id']]],
            ]);
            if (empty($object)) {
                throw new MethodNotAllowedException(__('Object not found or you are not authorised to see it.'));
            }
        }

        if ($this->request->is('ajax')) {
            $modules = [];

            if ($model === 'Attribute' || $model === 'ShadowAttribute') {
                foreach ($enabledModules['modules'] as $module) {
                    if (in_array($attribute[0]['Attribute']['type'], $module['mispattributes']['input'])) {
                        $modules[] = array('name' => $module['name'], 'description' => $module['meta']['description']);
                    }
                }
            }

            if ($model === 'Object') {
                foreach ($enabledModules['modules'] as $module) {
                    if (
                        in_array($object[0]['Object']['name'], $module['mispattributes']['input']) ||
                        in_array($object[0]['Object']['uuid'], $module['mispattributes']['input'])
                    ) {
                        $modules[] = array('name' => $module['name'], 'description' => $module['meta']['description']);
                    }
                }
            }

            $this->set('id', $id);
            $this->set('modules', $modules);
            $this->set('type', $type);
            $this->set('model', $model);
            $this->render('ajax/enrichmentChoice');
        } else {
            $options = [];
            $format = 'simplified';
            foreach ($enabledModules['modules'] as $temp) {
                if ($temp['name'] == $module) {
                    $format = !empty($temp['mispattributes']['format']) ? $temp['mispattributes']['format'] : 'simplified';
                    if (isset($temp['meta']['config'])) {
                        foreach ($temp['meta']['config'] as $conf) {
                            $options[$conf] = Configure::read('Plugin.' . $type . '_' . $module . '_' . $conf);
                        }
                    }
                    break;
                }
            }
            $distributions = $this->Event->Attribute->distributionLevels;
            $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
            if (empty($sgs)) {
                unset($distributions[4]);
            }
            $this->set('distributions', $distributions);
            $this->set('sgs', $sgs);
            $this->set('title_for_layout', __('Enrichment Results'));
            $this->set('title', __('Enrichment Results'));
            if ($format == 'misp_standard') {
                if ($model === 'Attribute' || $model === 'ShadowAttribute') {
                    $this->__queryEnrichment($attribute, $module, $options, $type);
                }

                if ($model === 'Object') {
                    $this->__queryObjectEnrichment($object, $module, $options, $type);
                }
            } else {
                $this->__queryOldEnrichment($attribute, $module, $options, $type);
            }
        }
    }

    private function __queryEnrichment($attribute, $module, $options, $type)
    {
        if ($this->Event->Attribute->typeIsAttachment($attribute[0]['Attribute']['type'])) {
            $attribute[0]['Attribute']['data'] = $this->Event->Attribute->base64EncodeAttachment($attribute[0]['Attribute']);
        }
        $event_id = $attribute[0]['Event']['id'];
        $data = array('module' => $module, 'attribute' => $attribute[0]['Attribute'], 'event_id' => $event_id);
        if (!empty($options)) {
            $data['config'] = $options;
        }
        $result = $this->Module->queryModuleServer($data, false, $type, false, $attribute[0]);
        if (!$result) {
            throw new InternalErrorException(__('%s service not reachable.', $type));
        }
        if (isset($result['error'])) {
            $this->Flash->error($result['error']);
        }
        if (!is_array($result)) {
            throw new Exception($result);
        }
        $event = $this->Event->handleMispFormatFromModuleResult($result);
        if (empty($event['Attribute']) && empty($event['Object'])) {
            $this->__handleSimplifiedFormat($attribute, $module, $options, $result, $type);
        } else {
            $importComment = !empty($result['comment']) ? $result['comment'] : $attribute[0]['Attribute']['value'] . __(': Enriched via the ') . $module . ($type != 'Enrichment' ? ' ' . $type : '')  . ' module';
            $this->set('importComment', $importComment);
            $event['Event'] = $attribute[0]['Event'];
            $org_name = $this->Event->Orgc->find('first', array(
                'conditions' => array('Orgc.id' => $event['Event']['orgc_id']),
                'fields' => array('Orgc.name')
            ));
            $event['Event']['orgc_name'] = $org_name['Orgc']['name'];
            if ($attribute[0]['Object']['id']) {
                $object_id = $attribute[0]['Object']['id'];
                $initial_object = $this->Event->fetchInitialObject($event_id, $object_id);
                if (!empty($initial_object)) {
                    $event['initialObject'] = $initial_object;
                }
            }
            $this->set('event', $event);
            $this->set('menuItem', 'enrichmentResults');
            $this->set('title_for_layout', __('Enrichment Results'));
            $this->set('title', __('Enrichment Results'));
            $this->render('resolved_misp_format');
        }
    }

    private function __queryObjectEnrichment($object, $module, $options, $type)
    {
        $object[0]['Object']['Attribute'] = $object[0]['Attribute'];
        foreach($object[0]['Object']['Attribute'] as &$attribute) {
            if ($this->Event->Attribute->typeIsAttachment($attribute['type'])) {
                $attribute['data'] = $this->Event->Attribute->base64EncodeAttachment($attribute);
            }
        }

        $event_id = $object[0]['Event']['id'];
        $data = array('module' => $module, 'object' => $object[0]['Object'], 'event_id' => $event_id);
        if (!empty($options)) {
            $data['config'] = $options;
        }
        $result = $this->Module->queryModuleServer($data, false, $type, false, $object[0]);
        if (!$result) {
            throw new InternalErrorException(__('%s service not reachable.', $type));
        }
        if (isset($result['error'])) {
            $this->Flash->error($result['error']);
        }
        if (!is_array($result)) {
            throw new Exception($result);
        }
        $event = $this->Event->handleMispFormatFromModuleResult($result);
        if (empty($event['Attribute']) && empty($event['Object'])) {
            throw new NotImplementedException(__('No Attribute or Object returned by the module.'));
        } else {
            $importComment = !empty($result['comment']) ? $result['comment'] : $object[0]['Object']['value'] . __(': Enriched via the ') . $module . ($type != 'Enrichment' ? ' ' . $type : '')  . ' module';
            $this->set('importComment', $importComment);
            $event['Event'] = $object[0]['Event'];
            $org_name = $this->Event->Orgc->find('first', array(
                'conditions' => array('Orgc.id' => $event['Event']['orgc_id']),
                'fields' => array('Orgc.name')
            ));
            $event['Event']['orgc_name'] = $org_name['Orgc']['name'];
            if ($attribute[0]['Object']['id']) {
                $object_id = $attribute[0]['Object']['id'];
                $initial_object = $this->Event->fetchInitialObject($event_id, $object_id);
                if (!empty($initial_object)) {
                    $event['initialObject'] = $initial_object;
                }
            }
            $this->set('event', $event);
            $this->set('menuItem', 'enrichmentResults');
            $this->set('title_for_layout', __('Enrichment Results'));
            $this->set('title', __('Enrichment Results'));
            $this->render('resolved_misp_format');
        }
    }

    private function __queryOldEnrichment($attribute, $module, $options, $type)
    {
        $data = array('module' => $module, $attribute[0]['Attribute']['type'] => $attribute[0]['Attribute']['value'], 'event_id' => $attribute[0]['Attribute']['event_id'], 'attribute_uuid' => $attribute[0]['Attribute']['uuid']);
        if ($this->Event->Attribute->typeIsAttachment($attribute[0]['Attribute']['type'])) {
            $data['data'] = $this->Event->Attribute->base64EncodeAttachment($attribute[0]['Attribute']);
        }
        if (!empty($options)) {
            $data['config'] = $options;
        }
        $result = $this->Module->queryModuleServer($data, false, $type, false, $attribute[0]);
        if (!$result) {
            throw new InternalErrorException(__('%s service not reachable.', $type));
        }
        if (isset($result['error'])) {
            $this->Flash->error($result['error']);
        }
        if (!is_array($result)) {
            throw new Exception($result);
        }
        $this->__handleSimplifiedFormat($attribute, $module, $options, $result, $type);
    }

    private function __handleSimplifiedFormat($attribute, $module, $options, $result, $type, $event = false)
    {
        $resultArray = $this->Event->handleModuleResult($result, $attribute[0]['Attribute']['event_id']);
        if (!empty($result['comment'])) {
            $importComment = $result['comment'];
        } else {
            $importComment = $attribute[0]['Attribute']['value'] . __(': Enriched via the %s', $module) . ($type != 'Enrichment' ? ' ' . $type : '')  . ' module';
        }
        $typeCategoryMapping = array();
        foreach ($this->Event->Attribute->categoryDefinitions as $k => $cat) {
            foreach ($cat['types'] as $type) {
                $typeCategoryMapping[$type][$k] = $k;
            }
        }
        $this->Event->Attribute->fetchRelated($this->Auth->user(), $resultArray);
        foreach ($resultArray as $key => $result) {
            if (isset($result['data'])) {
                App::uses('FileAccessTool', 'Tools');
                $tmpdir = Configure::read('MISP.tmpdir') ? Configure::read('MISP.tmpdir') : '/tmp';
                $tempFile = FileAccessTool::createTempFile($tmpdir, $prefix = 'MISP');
                FileAccessTool::writeToFile($tempFile, $result['data']);
                $resultArray[$key]['data'] = basename($tempFile) . '|' . filesize($tempFile);
            }
        }
        $this->set('type', $type);
        if (!$event){
            $this->set('event', array('Event' => $attribute[0]['Event']));
        }
        $this->set('resultArray', $resultArray);
        $this->set('typeDefinitions', $this->Event->Attribute->typeDefinitions);
        $this->set('typeCategoryMapping', $typeCategoryMapping);
        $this->set('defaultAttributeDistribution', $this->Event->Attribute->defaultDistribution());
        $this->set('importComment', $importComment);
        $this->render('resolved_attributes');
    }

    public function handleModuleResults($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
        }
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (!$event) {
            throw new NotFoundException(__('Invalid event.'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You don\'t have permission to do that.'));
        }

        $resolved_data = $this->_jsonDecode($this->request->data['Event']['JsonObject']);
        $data = $this->_jsonDecode($this->request->data['Event']['data']);
        if (!empty($data['initialObject'])) {
            $resolved_data['initialObject'] = $data['initialObject'];
        }
        unset($data);
        $default_comment = $this->request->data['Event']['default_comment'];
        $flashMessage = $this->Event->processModuleResultsDataRouter($this->Auth->user(), $resolved_data, $event['Event']['id'], $default_comment);
        $this->Flash->info($flashMessage);

        if ($this->request->is('ajax')) {
            return $this->RestResponse->viewData($flashMessage, $this->response->type());
        } else {
            $this->redirect(array('controller' => 'events', 'action' => 'view', $event['Event']['id']));
        }
    }

    public function importModule($moduleName, $eventId)
    {
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $eventId);
        if (!$event) {
            throw new NotFoundException(__('Invalid event.'));
        }
        $mayModify = $this->__canModifyEvent($event);
        $eventId = $event['Event']['id'];

        $this->loadModel('Module');
        $module = $this->Module->getEnabledModule($moduleName, 'Import');
        if (!is_array($module)) {
            throw new MethodNotAllowedException($module);
        }
        if (!isset($module['mispattributes']['inputSource'])) {
            $module['mispattributes']['inputSource'] = array('paste');
        }
        if ($this->request->is('post')) {
            $requestData = $this->request->data['Event'];
            $fail = false;
            $modulePayload = array(
                'module' => $module['name'],
                'event_id' => $eventId,
            );
            if (isset($module['meta']['config'])) {
                foreach ($module['meta']['config'] as $conf) {
                    $modulePayload['config'][$conf] = Configure::read('Plugin.Import_' . $moduleName . '_' . $conf);
                }
            }
            if ($moduleName === 'csvimport') {
                if (empty($requestData['config']['header']) && $requestData['config']['has_header'] === '1') {
                    $requestData['config']['header'] = ' ';
                }
                if (empty($requestData['config']['special_delimiter'])) {
                    $requestData['config']['special_delimiter'] = ' ';
                }
            }
            if (isset($module['mispattributes']['userConfig'])) {
                foreach ($module['mispattributes']['userConfig'] as $configName => $config) {
                    if (!$fail) {
                        if (isset($config['validation'])) {
                            if ($config['validation'] === '0' && $config['type'] == 'String') {
                                $validation = true;
                            }
                        } else {
                            $validationMethod = Module::CONFIG_TYPES[$config['type']]['validation'];
                            $validation = $this->Module->{$validationMethod}($requestData['config'][$configName]);
                        }
                        if ($validation !== true) {
                            $fail = ucfirst($configName) . ': ' . $validation;
                        } else {
                            if (isset($config['regex']) && !empty($config['regex'])) {
                                $fail = preg_match($config['regex'], $requestData['config'][$configName]) ? false : ucfirst($configName) . ': ' . 'Invalid setting' . ($config['errorMessage'] ? ' - ' . $config['errorMessage'] : '');
                                if (!empty($fail)) {
                                    $modulePayload['config'][$configName] = $requestData['config'][$configName];
                                }
                            } else {
                                $modulePayload['config'][$configName] = $requestData['config'][$configName];
                            }
                        }
                    }
                }
            }
            if (!$fail) {
                if (!empty($module['mispattributes']['inputSource'])) {
                    if (!isset($requestData['source'])) {
                        if (in_array('paste', $module['mispattributes']['inputSource'])) {
                            $requestData['source'] = '0';
                        } else {
                            $requestData['source'] = '1';
                        }
                    }
                    if ($requestData['source'] == '1') {
                        if (isset($requestData['data'])) {
                            $modulePayload['data'] = base64_decode($requestData['data']);
                        } elseif (empty($requestData['fileupload'])) {
                            $fail = __('Invalid file upload.');
                        } else {
                            $fileupload = $requestData['fileupload'];
                            if ((isset($fileupload['error']) && $fileupload['error'] == 0) || (!empty($fileupload['tmp_name']) && $fileupload['tmp_name'] != 'none') && is_uploaded_file($fileupload['tmp_name'])) {
                                $filename = basename($fileupload['name']);
                                $modulePayload['data'] = FileAccessTool::readAndDelete($fileupload['tmp_name']);
                            } else {
                                $fail = __('Invalid file upload.');
                            }
                        }
                    } else {
                        $modulePayload['data'] = $requestData['paste'];
                    }
                } else {
                    $modulePayload['data'] = '';
                }
                if (!$fail) {
                    $modulePayload['data'] = base64_encode($modulePayload['data']);
                    if (!empty($filename)) {
                        $modulePayload['filename'] = $filename;
                    }
                    $result = $this->Module->queryModuleServer($modulePayload, false, $moduleFamily = 'Import');
                    if (!$result) {
                        throw new InternalErrorException(__('Import service not reachable.'));
                    }
                    if (isset($result['error'])) {
                        $this->Flash->error($result['error']);
                    }
                    if (!is_array($result)) {
                        throw new Exception($result);
                    }
                    $importComment = !empty($result['comment']) ? $result['comment'] : 'Enriched via the ' . $module['name'] . ' module';
                    if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] === 'misp_standard') {
                        $resolvedEvent = $this->Event->handleMispFormatFromModuleResult($result);
                        $resolvedEvent['Event'] = $event['Event'];
                        if ($this->_isRest()) {
                            $this->Event->processModuleResultsDataRouter($this->Auth->user(), $resolvedEvent, $eventId, $importComment);
                            return $this->RestResponse->viewData($resolvedEvent, $this->response->type());
                        }
                        $this->set('event', $resolvedEvent);
                        $this->set('menuItem', 'importResults');
                        $render_name = 'resolved_misp_format';
                    } else {
                        $resultArray = $this->Event->handleModuleResult($result, $eventId);
                        if ($this->_isRest()) {
                            return $this->__pushFreetext(
                                $resultArray,
                                $event,
                                false,
                                false,
                                'soft'
                            );
                        }
                        $typeCategoryMapping = array();
                        foreach ($this->Event->Attribute->categoryDefinitions as $k => $cat) {
                            foreach ($cat['types'] as $type) {
                                $typeCategoryMapping[$type][$k] = $k;
                            }
                        }
                        $this->Event->Attribute->fetchRelated($this->Auth->user(), $resultArray);
                        $this->set('event', $event);
                        $this->set('resultArray', $resultArray);
                        $this->set('typeDefinitions', $this->Event->Attribute->typeDefinitions);
                        $this->set('typeCategoryMapping', $typeCategoryMapping);
                        $this->set('defaultAttributeDistribution', $this->Event->Attribute->defaultDistribution());
                        $render_name = 'resolved_attributes';
                    }

                    $distributionData = $this->Event->Attribute->fetchDistributionData($this->Auth->user());
                    $this->set('distributions', $distributionData['levels']);
                    $this->set('sgs', $distributionData['sgs']);
                    $this->set('title', __('Import Results'));
                    $this->set('title_for_layout', __('Import Results'));
                    $this->set('importComment', $importComment);
                    $this->render($render_name);
                }
            }
            if ($fail) {
                $this->Flash->error($fail);
            }
        }
        $this->set('configTypes', Module::CONFIG_TYPES);
        $this->set('module', $module);
        $this->set('eventId', $eventId);
        $this->set('event', $event);
        $this->set('mayModify', $mayModify);
    }

    public function exportModule($module, $id, $standard = false)
    {
        $result = $this->Event->export($this->Auth->user(), $module, array('eventid' => $id, 'standard' => $standard));
        $this->response->body(base64_decode($result['data']));
        $this->response->type($result['response']);
        $this->response->download('misp.event.' . $id . '.' . $module . '.export.' . $result['extension']);
        return $this->response;
    }

    public function toggleCorrelation($id)
    {
        if (!$this->_isSiteAdmin() && !Configure::read('MISP.allow_disabling_correlation')) {
            throw new MethodNotAllowedException(__('Disabling the correlation is not permitted on this instance.'));
        }
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You don\'t have permission to do that.'));
        }
        if ($this->request->is('post')) {
            if ($event['Event']['disable_correlation']) {
                $event['Event']['disable_correlation'] = 0;
                $this->Event->save($event);
                $this->Event->Attribute->Correlation->generateCorrelation(false, $event['Event']['id']);
            } else {
                $event['Event']['disable_correlation'] = 1;
                $this->Event->save($event);
                $this->Event->Attribute->Correlation->purgeCorrelations($event['Event']['id']);
            }
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('events', 'toggleCorrelation', $event['Event']['id'], false, 'Correlation ' . ($event['Event']['disable_correlation'] ? 'disabled' : 'enabled') . '.');
            } else {
                $this->Flash->success('Correlation ' . ($event['Event']['disable_correlation'] ? 'disabled' : 'enabled') . '.');
                $this->redirect(array('controller' => 'events', 'action' => 'view', $event['Event']['id']));
            }
        } else {
            $this->set('event', $event);
            $this->render('ajax/toggle_correlation');
        }
    }

    public function checkPublishedStatus($id)
    {
        $user = $this->_closeSession();
        $event = $this->Event->fetchSimpleEvent($user, $id, ['fields' => 'Event.published']);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        return new CakeResponse(array('body' => $event['Event']['published'], 'status' => 200, 'type' => 'txt'));
    }
    // #TODO i18n
    public function pushEventToZMQ($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        if ($this->request->is('Post')) {
            if (Configure::read('Plugin.ZeroMQ_enable')) {
                $pubSubTool = $this->Event->getPubSubTool();
                $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id, 'includeAllTags' => true));
                if (!empty($event)) {
                    $pubSubTool->publishEvent($event[0]);
                    $success = 1;
                    $message = 'Event published to ZMQ';
                } else {
                    $message = 'Invalid event.';
                }
            } else {
                $message = 'ZMQ event publishing not enabled.';
            }
        } else {
            $message = 'This functionality is only available via POST requests';
        }
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Events', 'pushEventToZMQ', $id, $this->response->type(), $message);
        } else {
            if (!empty($success)) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error($message);
            }
            $this->redirect($this->referer());
        }
    }

    public function pushEventToKafka($id)
    {
        if ($this->request->is('Post')) {
            $message = 'Kafka event publishing not enabled.';
            if (Configure::read('Plugin.Kafka_enable')) {
                $kafkaEventTopic = Configure::read('Plugin.Kafka_event_notifications_topic');
                $event = $this->Event->quickFetchEvent(array('eventid' => $id));
                if (Configure::read('Plugin.Kafka_event_notifications_enable') && !empty($kafkaEventTopic)) {
                    $kafkaPubTool = $this->Event->getKafkaPubTool();
                    if (!empty($event)) {
                        $kafkaPubTool->publishJson($kafkaEventTopic, $event, 'manual_publish');
                        $success = 1;
                        $message = 'Event published to Kafka';
                    } else {
                        $success = 0;
                        $message = 'Invalid event.';
                    }
                }
                $kafkaPubTopic = Configure::read('Plugin.Kafka_event_publish_notifications_topic');
                if (!empty($event['Event']['published']) && Configure::read('Plugin.Kafka_event_publish_notifications_enable') && !empty($kafkaPubTopic)) {
                    $kafkaPubTool = $this->Event->getKafkaPubTool();
                    $params = array('eventid' => $id, 'includeAllTags' => true);
                    if (Configure::read('Plugin.Kafka_include_attachments')) {
                        $params['includeAttachments'] = 1;
                    }
                    $event = $this->Event->fetchEvent($this->Auth->user(), $params);
                    if (!empty($event)) {
                        $kafkaPubTool->publishJson($kafkaPubTopic, $event[0], 'manual_publish');
                        if (!isset($success)) {
                            $success = 1;
                            $message = 'Event published to Kafka';
                        }
                    } else {
                        $success = 0;
                        $message = 'Invalid event.';
                    }
                }
            }
        } else {
            $message = 'This functionality is only available via POST requests';
        }
        if ($this->_isRest()) {
            return $this->RestResponse->saveSuccessResponse('Events', 'pushEventToKafka', $id, $this->response->type(), $message);
        } else {
            if (!empty($success)) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error($message);
            }
            $this->redirect($this->referer());
        }
    }

    public function getEventInfoById($id)
    {
        $user = $this->_closeSession();
        if (empty($id)) {
            throw new MethodNotAllowedException(__('Invalid ID.'));
        }
        $event = $this->Event->fetchSimpleEvent($user, $id, [
            'fields' => ['Event.id', 'Event.info', 'Event.threat_level_id', 'Event.analysis'],
            'contain' => ['EventTag' => ['Tag.id', 'Tag.name', 'Tag.colour'], 'ThreatLevel.name'],
        ]);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($event, $this->response->type());
        }

        if ($this->request->is('ajax')) {
            $this->layout = false;
        }
        $this->set('analysisLevels', $this->Event->analysisLevels);
        $this->set('validUuid', Validation::uuid($id));
        $this->set('id', $id);
        $this->set('event', $event);
    }

    public function enrichEvent($id)
    {
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (empty($event)) {
            throw new MethodNotAllowedException(__('Invalid Event'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }
        $this->Event->insertLock($this->Auth->user(), $event['Event']['id']);
        if ($this->request->is('post')) {
            $modules = array();
            if (!isset($this->request->data['Event'])) {
                $this->request->data = array('Event' => $this->request->data);
            }
            foreach ($this->request->data['Event'] as $module => $enabled) {
                if ($enabled) {
                    $modules[] = $module;
                }
            }
            $result = $this->Event->enrichmentRouter(array(
                'user' => $this->Auth->user(),
                'event_id' => $event['Event']['id'],
                'modules' => $modules
            ));
            if ($this->_isRest()) {
            } else {
                if ($result === true) {
                    $result = __('Enrichment task queued for background processing. Check back later to see the results.');
                }
                $this->Flash->success($result);
                $this->redirect('/events/view/' . $id);
            }
        } else {
            $this->loadModel('Module');
            $modules = $this->Module->getEnabledModules($this->Auth->user(), 'expansion');
            $this->layout = false;
            $this->set('modules', $modules);
            $this->render('ajax/enrich_event');
        }
    }

    public function addEventLock($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
        }

        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (empty($event)) {
            throw new MethodNotAllowedException(__('Invalid Event'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new UnauthorizedException(__('You do not have permission to do that.'));
        }

        $this->loadModel('EventLock');
        $lockId = $this->EventLock->insertLockApi($event['Event']['id'], $this->Auth->user());
        return $this->RestResponse->viewData(['lock_id' => $lockId], $this->response->type());
    }

    public function removeEventLock($id, $lockId)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
        }

        $event = $this->Event->fetchSimpleEvent($this->Auth->User(), $id);
        if (empty($event)) {
            throw new MethodNotAllowedException(__('Invalid Event'));
        }

        $this->loadModel('EventLock');
        $deleted = $this->EventLock->deleteApiLock($event['Event']['id'], $lockId, $this->Auth->user());
        return $this->RestResponse->viewData(['deleted' => $deleted], $this->response->type());
    }

    public function checkLocks($id, $timestamp)
    {
        $user = $this->_closeSession();

        $event = $this->Event->find('first', array(
            'recursive' => -1,
            'conditions' => ['Event.id' => $id],
            'fields' => ['Event.orgc_id', 'Event.timestamp', 'Event.user_id'],
        ));
        // Return empty response if event not found or user don't have permission to modify it
        if (empty($event) || !$this->__canModifyEvent($event, $user)) {
            return new CakeResponse(['status' => 204]);
        }

        $this->loadModel('EventLock');
        $locks = $this->EventLock->checkLock($user, $id);

        $editors = [];
        foreach ($locks as $t) {
            if ($t['type'] === 'user' && $t['User']['id'] !== $user['id']) {
                if (!$this->_isSiteAdmin() && $t['User']['org_id'] != $user['org_id']) {
                    $editors[] = __('another user');
                } else {
                    $editors[] = $t['User']['email'];
                }
            } else if ($t['type'] === 'job') {
                $editors[] = __('background job');
            } else if ($t['type'] === 'api') {
                $editors[] = __('external tool');
            }
        }
        $editors = array_unique($editors);

        if ($event['Event']['timestamp'] > $timestamp && empty($editors)) {
            $message = __('<b>Warning</b>: This event view is outdated. Please reload page to see the latest changes.');
            $this->set('class', 'alert');
        } else if ($event['Event']['timestamp'] > $timestamp) {
            $message = __('<b>Warning</b>: This event view is outdated, because is currently being edited by: %s. Please reload page to see the latest changes.', h(implode(', ', $editors)));
            $this->set('class', 'alert');
        } else if (empty($editors)) {
            return new CakeResponse(['status' => 204]);
        } else {
            $message = __('This event is currently being edited by: %s', h(implode(', ', $editors)));
            $this->set('class', 'alert alert-info');
        }

        $this->set('message', $message);
        $this->layout = false;
        $this->render('/Events/ajax/event_lock');
    }

    public function getEditStrategy($id)
    {
        // find the id of the event, change $id to it and proceed to read the event as if the ID was entered.
        $event = $this->Event->find('first', array(
            'recursive' => -1,
            'conditions' => Validation::uuid($id) ? ['Event.uuid' => $id] : ['Event.id' => $id],
            'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id', 'Event.user_id')
        ));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $response = array('extensions' => array());
        if ($this->__canModifyEvent($event)) {
            $response['strategy'] = 'edit';
        } else {
            $response['strategy'] = 'extend';
        }
        $extendedEvents = $this->Event->find('all', array(
            'recursive' => -1,
            'fields' => array('Event.id', 'Event.info', 'Event.uuid'),
            'conditions' => array(
                'Event.extends_uuid' => $event['Event']['uuid'],
                'Event.orgc_id' => $this->Auth->user('org_id')
            )
        ));
        foreach ($extendedEvents as $extendedEvent) {
            $response['extensions'][] = $extendedEvent['Event'];
        }
        return $this->RestResponse->viewData($response, $this->response->type());
    }
    public function upload_analysis_file($eventId)
    {
        $data = array();
        $this->set('eventId', $eventId);
        $this->set('file_uploaded', "0");
        $this->set('file_name', "");

        if (!$this->userRole['perm_modify']) {
            throw new UnauthorizedException('You do not have permission to do that.');
        }

        if ($this->request->is('post') && !empty($this->request['data']['Event']['analysis_file']['name'])) {
            $this->set('file_uploaded', "1");
            $this->set('file_name', $this->request['data']['Event']['analysis_file']['name']);
            $this->set('file_content', file_get_contents($this->request['data']['Event']['analysis_file']['tmp_name']));
        //$result = $this->Event->upload_mactime($this->Auth->user(), );
        } elseif ($this->request->is('post') && $this->request['data']['SelectedData']['mactime_data']) {
            // Find the event that is to be updated
            if (Validation::uuid($eventId)) {
                $eventFindParams['conditions']['Event.uuid'] = $eventId;
            } elseif (is_numeric($eventId)) {
                $eventFindParams['conditions']['Event.id'] = $eventId;
            } else {
                throw new NotFoundException(__('Invalid event.'));
            }
            $event = $this->Event->find('first', $eventFindParams);
            if (empty($event) || (!$this->_isSiteAdmin() && $event['Event']['orgc_id'] != $this->Auth->user('org_id'))) {
                throw new NotFoundException(__('Invalid event.'));
            }
            $eventId = $event['Event']['id'];

            $fileName = $this->request['data']['SelectedData']['mactime_file_name'];
            $fileData = $this->request['data']['SelectedData']['mactime_file_content'];
            $object = array();
        $data = json_decode($this->request['data']['SelectedData']['mactime_data'], true);
        $firstObject = 1;
            foreach ($data as $objectData) {
                $object['Object'] = array(
                    'name' => 'mactime-timeline-analysis',
                    'meta-category' => 'file',
                    'description' => 'Mactime template, used in forensic investigations to describe the timeline of a file activity',
                    'template_version' => 1,
                    'template_uuid' => '58149b06-eabe-4937-9dac-01d63f504e14'
                );

                $object['Attribute'] = array(
                    [
                        "event_id" => $eventId,
                        "category"=> "Other",
                        "type" => "text",
                        "to_ids" => false,
                        "distribution" => "5",
                        "object_relation" => "filepath",
                        "value" => $objectData['filepath']
                    ],
                    [
                        "event_id" => $eventId,
                        "category" => "Other",
                        "type" => "datetime",
                        "to_ids" => false,
                        "distribution" => "5",
                        "object_relation" => "datetime",
                        "value" => $objectData['time_accessed']
                    ],
                    [
                        "event_id" => $eventId,
                        "category" => "Other",
                        "type" => "text",
                        "to_ids" => false,
                        "distribution" => "5",
                        "object_relation" => "fileSize",
                        "value" => $objectData['file_size']
                    ],
                    [
                        "event_id" => $eventId,
                        "category" => "Other",
                        "type" => "text",
                        "to_ids" => false,
                        "distribution" => "5",
                        "object_relation" => "activityType",
                        "value" => $objectData['activity_type']
                    ],
                    [
                        "event_id" => $eventId,
                        "category" => "Other",
                        "type" => "text",
                        "to_ids" => false,
                        "distribution" => "5",
                        "object_relation" => "filePermissions",
                        "value" => $objectData['permissions']
                    ],
                    [
                        "event_id" => $eventId,
                        "category" => "External analysis",
                        "type" => "attachment",
                        "to_ids" => false,
                        "distribution" => "5",
                        "object_relation" => "file",
                        "value" => $fileName,
                        "data" => base64_encode($fileData),
                        "comment" => "Mactime source file"
                    ]

                    );
                $this->loadModel('MispObject');
                $ObjectResult = $this->MispObject->saveObject($object, $eventId, false, $this->Auth->user());
                $temp = $this->MispObject->ObjectReference->Object->find('first', array(
                    'recursive' => -1,
                    'fields' => array('Object.uuid','Object.id'),
                    'conditions' => array('Object.id' =>$ObjectResult)
                ));

                if ($firstObject === 0) {
                    $objectRef['referenced_id'] = $PreviousObjRef['Object']['id'];
                    $objectRef['referenced_uuid'] = $PreviousObjRef['Object']['uuid'];
                    $objectRef['object_id'] = $ObjectResult;
                    $objectRef['relationship_type'] = "preceded-by";
                    $this->loadModel('MispObject');
                    $result = $this->MispObject->ObjectReference->captureReference($objectRef, $eventId);
                    $objectRef['referenced_id'] = $temp['Object']['id'];
                    $objectRef['referenced_uuid'] = $temp['Object']['uuid'];
                    $objectRef['object_id'] = $PreviousObjRef['Object']['id'];
                    $objectRef['relationship_type'] = "followed-by";
                    $this->loadModel('MispObject');
                    $result = $this->MispObject->ObjectReference->captureReference($objectRef, $eventId);
                    $PreviousObjRef = $temp;
                } else {
                    $PreviousObjRef = $temp;
                    $firstObject = 0;
                }
            }
            $this->redirect('/events/view/' . $eventId);
        }
    }

    public function cullEmptyEvents()
    {
        $eventIds = $this->Event->find('list', array(
            'conditions' => array('Event.published' => 1),
            'fields' => array('Event.id', 'Event.uuid'),
            'recursive' => -1
        ));
        $count = 0;
        $this->Event->skipBlocklist = true;
        foreach ($eventIds as $eventId => $eventUuid) {
            $result = $this->Event->Attribute->find('first', array(
                'conditions' => array('Attribute.event_id' => $eventId),
                'recursive' => -1,
                'fields' => array('Attribute.id', 'Attribute.event_id')
            ));
            if (empty($result)) {
                $this->Event->delete($eventId);
                $count++;
            }
        }
        $this->Event->skipBlocklist = null;
        $message = __('%s event(s) deleted.', $count);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($message, $this->response->type());
        } else {
            $this->Flash->success($message);
            $this->redirect($this->referer());
        }
    }

    public function restoreDeletedEvents($force = false)
    {
        $startDate = '2020-07-31 00:00:00';
        $this->loadModel('AdminSetting');
        $endDate = date('Y-m-d H:i:s', $this->AdminSetting->getSetting('fix_login'));
        if (empty($endDate)) {
            $endDate = date('Y-m-d H:i:s', time());
        }
        $this->loadModel('Log');
        $redis = $this->Event->setupRedis();
        if ($force || ($redis && !$redis->exists('misp:event_recovery'))) {
            $deleted_events = $this->Log->findDeletedEvents(['created BETWEEN ? AND ?' => [$startDate, $endDate]]);
            $redis->set('misp:event_recovery', json_encode($deleted_events));
            $redis->expire('misp:event_recovery', 600);
        } else {
            $deleted_events = json_decode($redis->get('misp:event_recovery'), true);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($deleted_events, 'json');
        } else {
            $this->set('data', $deleted_events);
        }
    }

    public function recoverEvent($id, $mock = false)
    {
        if ($mock || !Configure::read('MISP.background_jobs')) {
            if ($this->request->is('post')) {
                $this->loadModel('Log');
                $result = $this->Log->recoverDeletedEvent($id, $mock);
                if ($mock) {
                    $message = __('Recovery simulation complete. Event #%s can be recovered using %s log entries.', $id, $result);
                } else {
                    $message = __('Recovery complete. Event #%s recovered, using %s log entries.', $id, $result);
                }
                if ($this->_isRest()) {
                    if ($mock) {
                        $results = $this->Log->mockLog;
                    } else {
                        $results = $this->Event->fetchEvent($this->Auth->user(), ['eventid' => $id]);
                    }
                    return $this->RestResponse->viewData($results, $this->response->type());
                } else {
                    $this->Flash->success($message);
                    if (!$mock) {
                        $this->redirect(['action' => 'restoreDeletedEvents']);
                    }
                }
            } else {
                $message = __('This action is only accessible via POST requests.');
                if ($this->_isRest()) {
                    return $this->RestResponse->viewData(array('message' => $message, 'error' => true), $this->response->type());
                } else {
                    $this->Flash->error($message);
                }
                $this->redirect(['action' => 'restoreDeletedEvents']);
            }
            $this->set('data', $this->Log->mockLog);
        } else {
            if ($this->request->is('post')) {
                $job_type = 'recover_event';
                $function = 'recoverEvent';
                $message = __('Bootstraping recovering of event %s', $id);
                $job = ClassRegistry::init('Job');
                $job->create();
                $data = array(
                    'worker' => 'prio',
                    'job_type' => $job_type,
                    'job_input' => sprintf('Event ID: %s', $id),
                    'status' => 0,
                    'retries' => 0,
                    'org_id' => 0,
                    'org' => 'ADMIN',
                    'message' => $message
                );
                $job->save($data);
                $jobId = $job->id;

                $this->Event->getBackgroundJobsTool()->enqueue(
                    BackgroundJobsTool::PRIO_QUEUE,
                    BackgroundJobsTool::CMD_EVENT,
                    [
                        $function,
                        $jobId,
                        $id
                    ],
                    true,
                    $jobId
                );

                $message = __('Recover event job queued. Job ID: %s', $jobId);
                if ($this->_isRest()) {
                    return $this->RestResponse->viewData(array('message' => $message), $this->response->type());
                } else {
                    $this->Flash->success($message);
                }
            } else {
                $message = __('This action is only accessible via POST requests.');
                if ($this->_isRest()) {
                    return $this->RestResponse->viewData(array('message' => $message, 'error' => true), $this->response->type());
                } else {
                    $this->Flash->error($message);
                }
            }
            $this->redirect(['action' => 'restoreDeletedEvents']);
        }
    }

    public function runTaxonomyExclusivityCheck($id)
    {
        if (Configure::read('MISP.disable_taxonomy_consistency_checks')) {
            return $this->RestResponse->saveFailResponse('Events', 'runTaxonomyExclusivityCheck', null, 'Taxonomy consistency checks are disabled, set `MISP.disable_taxonomy_consistency_checks` to `false` to enable them.', 'json');
        }

        $conditions = [];
        if (is_numeric($id)) {
            $conditions = array('eventid' => $id);
        } else if (Validation::uuid($id)) {
            $conditions = array('event_uuid' => $id);
        } else {
            throw new NotFoundException(__('Invalid event'));
        }
        $conditions['excludeLocalTags'] = false;
        $conditions['excludeGalaxy'] = true;
        $event = $this->Event->fetchEvent($this->Auth->user(), $conditions);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $event = $event[0];
        $this->loadModel('Taxonomy');
        $allConflicts = [];
        $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($event['EventTag']);
        if (!empty($tagConflicts['global']) || !empty($tagConflicts['local'])) {
            $tagConflicts['Event'] = $event['Event'];
            $allConflicts[] = $tagConflicts;
        }
        foreach ($event['Object'] as $k => $object) {
            if (isset($object['Attribute'])) {
                foreach ($object['Attribute'] as $k2 => $attribute) {
                    $this->Event->Attribute->removeGalaxyClusterTags($event['Object'][$k]['Attribute'][$k2]);
                    $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
                    if (!empty($tagConflicts['global']) || !empty($tagConflicts['local'])) {
                        $tagConflicts['Attribute'] = $event['Object'][$k]['Attribute'][$k2];
                        unset($tagConflicts['Attribute']['AttributeTag'], $tagConflicts['Attribute']['Galaxy'], $tagConflicts['Attribute']['ShadowAttribute']);
                        $allConflicts[] = $tagConflicts;
                    }
                }
            }
        }
        foreach ($event['Attribute'] as $k => $attribute) {
            $this->Event->Attribute->removeGalaxyClusterTags($event['Attribute'][$k]);
            $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
            if (!empty($tagConflicts['global']) || !empty($tagConflicts['local'])) {
                $tagConflicts['Attribute'] = $event['Attribute'][$k];
                unset($tagConflicts['Attribute']['AttributeTag'], $tagConflicts['Attribute']['Galaxy'], $tagConflicts['Attribute']['ShadowAttribute']);
                $allConflicts[] = $tagConflicts;
            }
        }
        return $this->RestResponse->viewData($allConflicts);
    }

    public function generateCount()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException();
        }
        // do one SQL query with the counts
        // loop over events, update in db
        $this->loadModel('MispAttribute');
        $events = $this->MispAttribute->find('all', array(
            'recursive' => -1,
            'fields' => array('event_id', 'count(event_id) as attribute_count'),
            'group' => array('Attribute.event_id'),
            'order' => array('Attribute.event_id ASC'),
        ));
        foreach ($events as $k => $event) {
            $this->Event->read(null, $event['Attribute']['event_id']);
            $this->Event->set('attribute_count', $event[0]['attribute_count']);
            $this->Event->save();
        }
        $this->Flash->success(__('All done. attribute_count generated from scratch for ' . (isset($k) ? $k : 'no') . ' events.'));
        $this->redirect(array('controller' => 'pages', 'action' => 'display', 'administration'));
    }

    /**
     * @param array $event
     * @return CakeResponseFile
     * @throws Exception
     */
    private function __restResponse(array $event)
    {
        $tmpFile = new TmpFileTool();

        if ($this->request->is('json')) {
            App::uses('JSONConverterTool', 'Tools');
            if ($this->RestResponse->isAutomaticTool() && empty($event['Event']['protected'])) {
                foreach (JSONConverterTool::streamConvert($event) as $part) {
                    $tmpFile->write($part);
                }
            } else {
                $tmpFile->write(JSONConverterTool::convert($event));
            }
            $format = 'json';
        } elseif ($this->request->is('xml')) {
            App::uses('XMLConverterTool', 'Tools');
            $converter = new XMLConverterTool();
            foreach ($converter->frameCollection($converter->convert($event)) as $chunk) {
                $tmpFile->write($chunk);
            }
            $format = 'xml';
        } else {
            throw new Exception("Invalid format, only JSON or XML is supported.");
        }
        return $this->RestResponse->viewData($tmpFile, $format, false, true);
    }

    public function protect($id)
    {
        return $this->__toggleProtect($id, true);
    }

    public function unprotect($id)
    {
        return $this->__toggleProtect($id, false);
    }

    /**
     * @param string|int $id Event ID or UUID
     * @param bool $protect
     * @return CakeResponse|void
     * @throws Exception
     */
    private function __toggleProtect($id, $protect)
    {
        $event = $this->Event->fetchSimpleEvent($this->Auth->user(), $id);
        if (empty($event) || !$this->__canModifyEvent($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if ($this->request->is('post')) {
            $event['Event']['protected'] = $protect;
            $event['Event']['timestamp'] = time();
            $event['Event']['published'] = false;
            if ($this->Event->save($event)) {
                $message = __('Event switched to %s mode.', $protect ? __('protected') : __('unprotected'));
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('events', $protect ? 'protect' : 'unprotect', $event['Event']['id'], false, $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(['controller' => 'events', 'action' => 'view', $id]);
                }
            } else {
                $message = __('Something went wrong - could not switch event to %s mode.', $protect ? __('protected') : __('unprotected'));
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Events', $protect ? 'protect' : 'unprotect', $event['Event']['id'], $message);
                } else {
                    $this->Flash->error($message);
                    $this->redirect(['controller' => 'events', 'action' => 'view', $event['Event']['id']]);
                }
            }
        } else {
            $this->set('id', $event['Event']['id']);
            $this->set('title', $protect ? __('Protect event') : __('Remove event protection'));
            $this->set(
                'question',
                $protect ?
                __('Are you sure you want switch the event to protected mode? The event and its subsequent modifications will be rejected by MISP instances that you synchronise with, unless the hop through which the event is propagated has their signing key in the list of event signing keys.'):
                __('Are you sure you want to switch the event to unprotected mode? Unprotected mode is the default behaviour of MISP events, with creation and modification being purely limited by the distribution mechanism and eligible sync users.')
            );
            $this->set('actionName', $protect ? __('Switch to protected mode') : __('Remove protected mode'));
            $this->layout = false;
            $this->render('/genericTemplates/confirm');
        }
    }

    /**
     * @param array $event
     * @return void
     */
    private function __setHighlightedTags($event)
    {
        $this->loadModel('Taxonomy');
        $highlightedTags = $this->Taxonomy->getHighlightedTags($this->Taxonomy->getHighlightedTaxonomies(), $event['EventTag']);
        $this->set('highlightedTags', $highlightedTags);
    }

    /**
     *
     * @param array $events
     * @return array
     */
    private function __attachHighlightedTagsToEvents($events)
    {
        $this->loadModel('Taxonomy');
        $highlightedTaxonomies = $this->Taxonomy->getHighlightedTaxonomies();
        foreach ($events as $k => $event) {
            $events[$k]['Event']['highlightedTags'] = $this->Taxonomy->getHighlightedTags($highlightedTaxonomies, $event['EventTag']);
        }

        return $events;
    }
}
