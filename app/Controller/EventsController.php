<?php
App::uses('AppController', 'Controller');
App::uses('Xml', 'Utility');

class EventsController extends AppController
{
    public $components = array(
            'Security',
            'Email',
            'RequestHandler',
            'IOCImport',
            'Cidr'
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

    private $acceptedFilteringNamedParams = array(
        'sort', 'direction', 'focus', 'extended', 'overrideLimit', 'filterColumnsOverwrite', 'attributeFilter', 'extended', 'page',
        'searchFor', 'proposal', 'correlation', 'warning', 'deleted', 'includeRelatedTags', 'includeDecayScore', 'distribution',
        'taggedAttributes', 'galaxyAttachedAttributes', 'objectType', 'attributeType', 'focus', 'extended', 'overrideLimit',
        'filterColumnsOverwrite', 'feed', 'server', 'toIDS', 'sighting', 'includeSightingdb'
    );

    public $defaultFilteringRules =  array(
        'searchFor' => '',
        'attributeFilter' => 'all',
        'proposal' => 0,
        'correlation' => 0,
        'warning' => 0,
        'deleted' => 2,
        'includeRelatedTags' => 0,
        'includeDecayScore' => 0,
        'toIDS' => 0,
        'feed' => 0,
        'server' => 0,
        'distribution' => array(0, 1, 2, 3, 4, 5),
        'sighting' => 0,
        'taggedAttributes' => '',
        'galaxyAttachedAttributes' => ''
    );

    public $helpers = array('Js' => array('Jquery'));

    public $paginationFunctions = array('index', 'proposalEventIndex');

    public function beforeFilter()
    {
        parent::beforeFilter();

        // what pages are allowed for non-logged-in users
        $this->Auth->allow('xml');
        $this->Auth->allow('csv');
        $this->Auth->allow('nids');
        $this->Auth->allow('hids_md5');
        $this->Auth->allow('hids_sha1');
        $this->Auth->allow('text');
        $this->Auth->allow('restSearch');
        $this->Auth->allow('stix');
        $this->Auth->allow('stix2');

        $this->Security->unlockedActions[] = 'viewEventAttributes';

        // TODO Audit, activate logable in a Controller
        if (count($this->uses) && $this->{$this->modelClass}->Behaviors->attached('SysLogLogable')) {
            $this->{$this->modelClass}->setUserData($this->activeUser);
        }

        // convert uuid to id if present in the url, and overwrite id field
        if (isset($this->params->query['uuid'])) {
            $params = array(
                    'conditions' => array('Event.uuid' => $this->params->query['uuid']),
                    'recursive' => 0,
                    'fields' => 'Event.id'
            );
            $result = $this->Event->find('first', $params);
            if (isset($result['Event']) && isset($result['Event']['id'])) {
                $id = $result['Event']['id'];
                $this->params->addParams(array('pass' => array($id))); // FIXME find better way to change id variable if uuid is found. params->url and params->here is not modified accordingly now
            }
        }

        // if not admin or own org, check private as well..
        if (!$this->_isSiteAdmin() && in_array($this->action, $this->paginationFunctions)) {
            $sgids = $this->Event->cacheSgids($this->Auth->user(), true);
            $conditions = array(
                'AND' => array(
                    array(
                        "OR" => array(
                            array(
                                'Event.org_id' => $this->Auth->user('org_id')
                            ),
                            array(
                                'AND' => array(
                                        'Event.distribution >' => 0,
                                        'Event.distribution <' => 4,
                                        Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
                                ),
                            ),
                            array(
                                'AND' => array(
                                        'Event.distribution' => 4,
                                        'Event.sharing_group_id' => $sgids,
                                        Configure::read('MISP.unpublishedprivate') ? array('Event.published =' => 1) : array(),
                                ),
                            )
                        )
                    )
                )
            );
            if ($this->userRole['perm_sync'] && $this->Auth->user('Server')['push_rules']) {
                $conditions['AND'][] = $this->Event->filterRulesToConditions($this->Auth->user('Server')['push_rules']);
            }
            $this->paginate = Set::merge($this->paginate, array('conditions' => $conditions));
        }
    }

    private function __filterOnAttributeValue($value)
    {
        // dissect the value
        $pieces = explode('|', $value);
        $include = array();
        $exclude = array();
        $includeIDs = array();
        $excludeIDs = array();
        foreach ($pieces as $piece) {
            if ($piece[0] == '!') {
                $exclude[] =  '%' . strtolower(substr($piece, 1)) . '%';
            } else {
                $include[] = '%' . strtolower($piece) . '%';
            }
        }
        if (!empty($include)) {
            // get all of the attributes that should be included
            $includeQuery = array(
                    'recursive' => -1,
                    'fields' => array('id', 'event_id', 'distribution', 'value1', 'value2'),
                    'conditions' => array(),
            );
            foreach ($include as $i) {
                $includeQuery['conditions']['OR'][] = array('lower(Attribute.value1) LIKE' => $i);
                $includeQuery['conditions']['OR'][] = array('lower(Attribute.value2) LIKE' => $i);
            }
            $includeQuery['conditions']['AND'][] = array('Attribute.deleted' => 0);
            $includeHits = $this->Event->Attribute->find('all', $includeQuery);

            // convert it into an array that uses the event ID as a key
            foreach ($includeHits as $iH) {
                $includeIDs[$iH['Attribute']['event_id']][] = array('attribute_id' => $iH['Attribute']['id'], 'distribution' => $iH['Attribute']['distribution']);
            }
        }

        if (!empty($exclude)) {
            // get all of the attributes that should be excluded
            $excludeQuery = array(
                'recursive' => -1,
                'fields' => array('id', 'event_id', 'distribution', 'value1', 'value2'),
                'conditions' => array(),
            );
            foreach ($exclude as $e) {
                $excludeQuery['conditions']['OR'][] = array('lower(Attribute.value1) LIKE' => $e);
                $excludeQuery['conditions']['OR'][] = array('lower(Attribute.value2) LIKE' => $e);
            }
            $excludeQuery['conditions']['AND'][] = array('Attribute.deleted' => 0);
            $excludeHits = $this->Event->Attribute->find('all', $excludeQuery);

            // convert it into an array that uses the event ID as a key
            foreach ($excludeHits as $eH) {
                $excludeIDs[$eH['Attribute']['event_id']][] = array('attribute_id' => $eH['Attribute']['id'], 'distribution' => $eH['Attribute']['distribution']);
            }
        }
        $includeIDs = array_keys($includeIDs);
        $excludeIDs = array_keys($excludeIDs);
        // return -1 as the only value in includedIDs if both arrays are empty. This will mean that no events will be shown if there was no hit
        if (empty($includeIDs) && empty($excludeIDs)) {
            $includeIDs[] = -1;
        }
        return array($includeIDs, $excludeIDs);
    }

    private function __quickFilter($value)
    {
        if (!is_array($value)) {
            $value = array($value);
        }
        $values = array();
        foreach ($value as $v) {
            $values[] = '%' . strtolower($v) . '%';
        }

        $result = array();
        // get all of the attributes that have a hit on the search term, in either the value or the comment field
        // This is not perfect, the search will be case insensitive, but value1 and value2 are searched separately. lower() doesn't seem to work on virtualfields
        $subconditions = array();
        foreach ($values as $v) {
            $subconditions[] = array('lower(value1) LIKE' => $v);
            $subconditions[] = array('lower(value2) LIKE' => $v);
            $subconditions[] = array('lower(Attribute.comment) LIKE' => $v);
        }
        $conditions = array(
            'AND' => array(
                'OR' => $subconditions,
                'Attribute.deleted' => 0
            )
        );
        $attributeHits = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array(
                'conditions' => $conditions,
                'fields' => array('event_id', 'comment', 'distribution', 'value1', 'value2'),
                'flatten' => 1
        ));
        // rearrange the data into an array where the keys are the event IDs
        $eventsWithAttributeHits = array();
        foreach ($attributeHits as $aH) {
            $eventsWithAttributeHits[$aH['Attribute']['event_id']][] = $aH['Attribute'];
        }

        // Using the keys from the previously obtained ordered array, let's fetch all of the events involved
        $events = $this->Event->find('all', array(
                'recursive' => -1,
                'fields' => array('id', 'distribution', 'org_id'),
                'conditions' => array('id' => array_keys($eventsWithAttributeHits)),
        ));

        foreach ($events as $event) {
            $result[] = $event['Event']['id'];
        }

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
                'fields' => array('name', 'id'),
                'contain' => array('EventTag', 'AttributeTag'),
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
        $conditions = array();
        $orgs = $this->Event->Org->find('list', array(
                'conditions' => $subconditions,
                'recursive' => -1,
                'fields' => array('id')
        ));
        foreach ($values as $v) {
            $conditions['OR'][] = array('lower(info) LIKE' => $v);
            $conditions['OR'][] = array('lower(uuid) LIKE' => $v);
        }
        if (!empty($orgs)) {
            $conditions['OR']['orgc_id'] = array_values($orgs);
        }
        $otherEvents = $this->Event->find('all', array(
                'recursive' => -1,
                'fields' => array('id', 'orgc_id', 'info', 'uuid'),
                'conditions' => $conditions,
        ));
        foreach ($otherEvents as $oE) {
            if (!in_array($oE['Event']['id'], $result)) {
                $result[] = $oE['Event']['id'];
            }
        }
        return $result;
    }

    private function __setIndexFilterConditions($passedArgs, $urlparams)
    {
        $passedArgsArray = array();
        foreach ($passedArgs as $k => $v) {
            if (substr($k, 0, 6) === 'search') {
                if (!is_array($v)) {
                    if ($urlparams != "") {
                        $urlparams .= "/";
                    }
                    $urlparams .= $k . ":" . $v;
                }
                $searchTerm = strtolower(substr($k, 6));
                switch ($searchTerm) {
                    case 'all':
                        if (!empty($passedArgs['searchall'])) {
                            $this->paginate['conditions']['AND'][] = array('Event.id' => $this->__quickFilter($passedArgs['searchall']));
                        }
                        break;
                    case 'attribute':
                        $event_id_arrays = $this->__filterOnAttributeValue($v);
                        foreach ($event_id_arrays[0] as $event_id) {
                            $this->paginate['conditions']['AND']['OR'][] = array('Event.id' => $event_id);
                        }
                        foreach ($event_id_arrays[1] as $event_id) {
                            $this->paginate['conditions']['AND'][] = array('Event.id !=' => $event_id);
                        }
                        break;
                    case 'published':
                        if ($v == 2) {
                            continue 2;
                        }
                        $this->paginate['conditions']['AND'][] = array('Event.' . substr($k, 6) . ' =' => $v);
                        break;
                    case 'hasproposal':
                        if ($v == 2) {
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
                        $pieces = explode('|', $v);
                        $temp = array();
                        foreach ($pieces as $piece) {
                            $piece = trim($piece);
                            if ($piece[0] == '!') {
                                if (strlen($piece) == 37) {
                                    $this->paginate['conditions']['AND'][] = array('Event.uuid !=' => substr($piece, 1));
                                } else {
                                    $this->paginate['conditions']['AND'][] = array('Event.id !=' => substr($piece, 1));
                                }
                            } else {
                                if (strlen($piece) == 36) {
                                    $temp['OR'][] = array('Event.uuid' => $piece);
                                } else {
                                    $temp['OR'][] = array('Event.id' => $piece);
                                }
                            }
                        }
                        $this->paginate['conditions']['AND'][] = $temp;
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
                        if (preg_match('/^[0-9]+[mhdw]$/i', $v)) {
                            $v = $this->Event->resolveTimeDelta($v);
                        }
                        $this->paginate['conditions']['AND'][] = array('Event.timestamp >=' => $v);
                        break;
                    case 'publish_timestamp':
                    case 'publishtimestamp':
                        if ($v == "") {
                            continue 2;
                        }
                        if (is_array($v) && isset($v[0]) && isset($v[1])) {
                            if (preg_match('/^[0-9]+[mhdw]$/i', $v[0])) {
                                $v[0] = $this->Event->resolveTimeDelta($v[0]);
                            }
                            if (preg_match('/^[0-9]+[mhdw]$/i', $v[1])) {
                                $v[1] = $this->Event->resolveTimeDelta($v[1]);
                            }
                            $this->paginate['conditions']['AND'][] = array('Event.publish_timestamp >=' => $v[0]);
                            $this->paginate['conditions']['AND'][] = array('Event.publish_timestamp <=' => $v[1]);
                        } else {
                            if (preg_match('/^[0-9]+[mhdw]$/i', $v)) {
                                $v = $this->Event->resolveTimeDelta($v);
                            }
                            $this->paginate['conditions']['AND'][] = array('Event.publish_timestamp >=' => $v);
                        }
                        break;
                    case 'org':
                        if ($v == "") {
                            continue 2;
                        }
                        if (!Configure::read('MISP.showorg')) {
                            continue 2;
                        }
                        $orgArray = $this->Event->Org->find('list', array('fields' => array('Org.name')));
                        $orgUuidArray = $this->Event->Org->find('list', array('fields' => array('Org.uuid')));
                        $orgArray = array_map('strtoupper', $orgArray);
                        // if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
                        $pieces = explode('|', $v);
                        $test = array();
                        foreach ($pieces as $piece) {
                            if ($piece[0] == '!') {
                                if (is_numeric(substr($piece, 1))) {
                                    $this->paginate['conditions']['AND'][] = array('Event.orgc_id !=' => substr($piece, 1));
                                } else {
                                    if (Validation::uuid(substr($piece, 1))) {
                                        $org_id = array_search(substr($piece, 1), $orgUuidArray);
                                    } else {
                                        $org_id = array_search(strtoupper(substr($piece, 1)), $orgArray);
                                    }
                                    if ($org_id) {
                                        $this->paginate['conditions']['AND'][] = array('Event.orgc_id !=' => $org_id);
                                    }
                                }
                            } else {
                                if (is_numeric($piece)) {
                                    $test['OR'][] = array('Event.orgc_id' => array('Event.orgc_id' => $piece));
                                } else {
                                    if (Validation::uuid($piece)) {
                                        $org_id = array_search($piece, $orgUuidArray);
                                    } else {
                                        $org_id = array_search(strtoupper($piece), $orgArray);
                                    }
                                    if ($org_id) {
                                        $test['OR'][] = array('Event.orgc_id' => $org_id);
                                    } else {
                                        $test['OR'][] = array('Event.orgc_id' => -1);
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
                            if ($piece[0] == '!') {
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
                            if ($piece[0] == '!') {
                                $this->paginate['conditions']['AND'][] = array('lower(Event.info)' . ' NOT LIKE' => '%' . strtolower(substr($piece, 1)) . '%');
                            } else {
                                $test['OR'][] = array('lower(Event.info)' . ' LIKE' => '%' . strtolower($piece) . '%');
                            }
                        }
                        $this->paginate['conditions']['AND'][] = $test;
                        break;
                    case 'tag':
                    case 'tags':
                        if (!$v || !Configure::read('MISP.tagging') || $v === 0) {
                            continue 2;
                        }
                        if (!is_array($v)) {
                            $pieces = explode('|', $v);
                        } else {
                            $pieces = $v;
                        }
                        $filterString = "";
                        $expectOR = false;
                        $setOR = false;
                        foreach ($pieces as $piece) {
                            if ($piece[0] == '!') {
                                if (is_numeric(substr($piece, 1))) {
                                    $conditions = array('OR' => array('Tag.id' => substr($piece, 1)));
                                } else {
                                    $conditions = array('OR' => array('Tag.name' => substr($piece, 1)));
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
                                $block = $this->Event->EventTag->find('all', array(
                                        'conditions' => array('EventTag.tag_id' => $tagName['Tag']['id']),
                                        'fields' => 'event_id',
                                        'recursive' => -1,
                                ));
                                if (!empty($block)) {
                                    $sqlSubQuery = 'Event.id NOT IN (';
                                    foreach ($block as $b) {
                                        $sqlSubQuery .= $b['EventTag']['event_id'] . ',';
                                    }
                                    $this->paginate['conditions']['AND'][] = substr($sqlSubQuery, 0, -1) . ')';
                                }
                                if ($filterString != "") {
                                    $filterString .= "|";
                                }
                                $filterString .= '!' . (isset($tagName['Tag']['name']) ? $tagName['Tag']['name'] : $piece);
                            } else {
                                $expectOR = true;
                                if (is_numeric($piece)) {
                                    $conditions = array('OR' => array('Tag.id' => $piece));
                                } else {
                                    $conditions = array('OR' => array('Tag.name' => $piece));
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

                                $allow = $this->Event->EventTag->find('all', array(
                                        'conditions' => array('EventTag.tag_id' => $tagName['Tag']['id']),
                                        'fields' => 'event_id',
                                        'recursive' => -1,
                                ));
                                if (!empty($allow)) {
                                    $sqlSubQuery = 'Event.id IN (';
                                    foreach ($allow as $a) {
                                        $setOR = true;
                                        $sqlSubQuery .= $a['EventTag']['event_id'] . ',';
                                    }
                                    $this->paginate['conditions']['AND']['OR'][] = substr($sqlSubQuery, 0, -1) . ')';
                                }
                                if ($filterString != "") {
                                    $filterString .= "|";
                                }
                                $filterString .= isset($tagName['Tag']['name']) ? $tagName['Tag']['name'] : $piece;
                            }
                        }
                        // If we have a list of OR-d arguments, we expect to end up with a list of allowed event IDs
                        // If we don't however, it means that none of the tags was found. To prevent displaying the entire event index in this case:
                        if ($expectOR && !$setOR) {
                            $this->paginate['conditions']['AND'][] = array('Event.id' => -1);
                        }
                        $v = $filterString;
                        break;
                    case 'email':
                        if ($v == "" || (strtolower($this->Auth->user('email')) !== strtolower(trim($v)) && !$this->_isSiteAdmin())) {
                            continue 2;
                        }
                        // if the first character is '!', search for NOT LIKE the rest of the string (excluding the '!' itself of course)
                        $pieces = explode('|', $v);
                        $test = array();
                        foreach ($pieces as $piece) {
                            if ($piece[0] == '!') {
                                $users = $this->Event->User->find('list', array(
                                        'recursive' => -1,
                                        'fields' => array('User.email'),
                                        'conditions' => array('lower(User.email) LIKE' => '%' . strtolower(substr($piece, 1)) . '%')
                                ));
                                if (!empty($users)) {
                                    $this->paginate['conditions']['AND'][] = array('Event.user_id !=' => array_keys($users));
                                }
                            } else {
                                $users = $this->Event->User->find('list', array(
                                        'recursive' => -1,
                                        'fields' => array('User.email'),
                                        'conditions' => array('lower(User.email) LIKE' => '%' . strtolower($piece) . '%')
                                ));
                                if (!empty($users)) {
                                    $test['OR'][] = array('Event.user_id' => array_keys($users));
                                }
                            }
                        }

                        if (!empty($test)) {
                            $this->paginate['conditions']['AND'][] = $test;
                        }
                        break;
                    case 'distribution':
                    case 'analysis':
                    case 'threatlevel':
                        if ($v == "") {
                            continue 2;
                        }
                        $terms = array();
                        $filterString = "";
                        $searchTermInternal = $searchTerm;
                        if ($searchTerm == 'threatlevel') {
                            $searchTermInternal = 'threat_level_id';
                            $threatLevels = $this->Event->ThreatLevel->find('all', array(
                                'recursive' => -1,
                                'fields' => array('id', 'name'),
                            ));
                            foreach ($threatLevels as $tl) {
                                $terms[$tl['ThreatLevel']['id']] = $tl['ThreatLevel']['name'];
                            }
                        } elseif ($searchTerm == 'analysis') {
                            $terms = $this->Event->analysisLevels;
                        } else {
                            $terms = $this->Event->distributionLevels;
                        }
                        $pieces = explode('|', $v);
                        $test = array();
                        foreach ($pieces as $piece) {
                            if ($filterString != "") {
                                $filterString .= '|';
                            }
                            if ($piece[0] == '!') {
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
                        $this->paginate['conditions']['AND'][] = array('NOT' => array('Event.attribute_count' => 0));
                        break;
                    default:
                        continue 2;
                        break;
                }
                $passedArgsArray[$searchTerm] = $v;
            }
        }
        return $passedArgsArray;
    }

    public function index()
    {
        // list the events
        $urlparams = "";
        $overrideAbleParams = array('all', 'attribute', 'published', 'eventid', 'datefrom', 'dateuntil', 'org', 'eventinfo', 'tag', 'tags', 'distribution', 'sharinggroup', 'analysis', 'threatlevel', 'email', 'hasproposal', 'timestamp', 'publishtimestamp', 'publish_timestamp', 'minimal');
        $paginationParams = array('limit', 'page', 'sort', 'direction', 'order');
        $passedArgs = $this->passedArgs;
        if (isset($this->request->data)) {
            if (isset($this->request->data['request'])) {
                $this->request->data = $this->request->data['request'];
            }
            foreach ($this->request->data as $k => $v) {
                if (substr($k, 0, 6) === 'search' && in_array(strtolower(substr($k, 6)), $overrideAbleParams)) {
                    unset($this->request->data[$k]);
                    $this->request->data[strtolower(substr($k, 6))] = $v;
                } else if (in_array(strtolower($k), $overrideAbleParams)) {
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
        $this->set('passedArgs', json_encode($passedArgs));
        // check each of the passed arguments whether they're a filter (could also be a sort for example) and if yes, add it to the pagination conditions
        $passedArgsArray = $this->__setIndexFilterConditions($passedArgs, $urlparams);
        if (!$this->_isRest()) {
            $this->paginate['contain'] = array_merge($this->paginate['contain'], array('User.email', 'EventTag'));
        } else {
            $this->paginate['contain'] = array_merge($this->paginate['contain'], array('User.email'));
        }
        $this->set('urlparams', $urlparams);
        $this->set('passedArgsArray', $passedArgsArray);
        $this->paginate = Set::merge($this->paginate, array('contain' => array(
            'ThreatLevel' => array(
                'fields' => array(
                    'ThreatLevel.name'))
            ),
        ));
        $this->loadModel('GalaxyCluster');

        // for REST, don't use the pagination. With this, we'll escape the limit of events shown on the index.
        if ($this->_isRest()) {
            $rules = array();
            $fieldNames = array_keys($this->Event->getColumnTypes());
            $directions = array('ASC', 'DESC');
            if (isset($passedArgs['sort']) && in_array($passedArgs['sort'], $fieldNames)) {
                if (isset($passedArgs['direction']) && in_array(strtoupper($passedArgs['direction']), $directions)) {
                    $rules['order'] = array('Event.' . $passedArgs['sort'] => $passedArgs['direction']);
                } else {
                    $rules['order'] = array('Event.' . $passedArgs['sort'] => 'ASC');
                }
            } else {
                $rules['order'] = array('Event.id' => 'DESC');
            }
            $rules['contain'] = $this->paginate['contain'];
            if (isset($this->paginate['conditions'])) {
                $rules['conditions'] = $this->paginate['conditions'];
            }
            if (!empty($passedArgs['searchminimal'])) {
                unset($rules['contain']);
                $rules['recursive'] = -1;
                $rules['fields'] = array('id', 'timestamp', 'sighting_timestamp', 'published', 'uuid');
                $rules['contain'] = array('Orgc.uuid');
            }
            $paginationRules = array('page', 'limit', 'sort', 'direction', 'order');
            foreach ($paginationRules as $paginationRule) {
                if (isset($passedArgs[$paginationRule])) {
                    $rules[$paginationRule] = $passedArgs[$paginationRule];
                }
            }
            $counting_rules = $rules;
            if (!empty($counting_rules['limit'])) {
                unset($counting_rules['limit']);
            }
            if (!empty($counting_rules['page'])) {
                unset($counting_rules['page']);
            }
            $absolute_total = $this->Event->find('count', $counting_rules);
            if (empty($rules['limit'])) {
                $events = array();
                $i = 1;
                $continue = true;
                $rules['limit'] = 20000;
                while ($continue) {
                    $rules['page'] = $i;
                    $temp = $this->Event->find('all', $rules);
                    if (!empty($temp)) {
                        $events = array_merge($events, $temp);
                    } else {
                        $continue = false;
                    }
                    $i += 1;
                }
            } else {
                $events = $this->Event->find('all', $rules);
            }
            $total_events = count($events);
            foreach ($events as $k => $event) {
                if (empty($event['SharingGroup']['name'])) {
                    unset($events[$k]['SharingGroup']);
                }
            }
            if (empty($passedArgs['searchminimal'])) {
                $passes = ceil($total_events / 1000);
                for ($i = 0; $i < $passes; $i++) {
                    $event_tag_objects = array();
                    $event_tag_ids = array();
                    $elements = 1000;
                    if ($i == ($passes-1)) {
                        $elements = ($total_events % 1000);
                    }
                    for ($j = 0; $j < $elements; $j++) {
                        $event_tag_ids[$events[($i*1000) + $j]['Event']['id']] = array();
                    }
                    $eventTags = $this->Event->EventTag->find('all', array(
                        'recursive' => -1,
                        'conditions' => array(
                            'EventTag.event_id' => array_keys($event_tag_ids)
                        ),
                        'contain' => array(
                            'Tag' => array(
                                'conditions' => array('Tag.exportable' => 1),
                                'fields' => array('Tag.id', 'Tag.name', 'Tag.colour')
                            )
                        )
                    ));
                    foreach ($eventTags as $ket => $et) {
                        if (empty($et['Tag']['id'])) {
                            unset($eventTags[$ket]);
                        } else {
                            $et['EventTag']['Tag'] = $et['Tag'];
                            unset($et['Tag']);
                            if (empty($event_tag_objects[$et['EventTag']['event_id']])) {
                                $event_tag_objects[$et['EventTag']['event_id']] = array($et['EventTag']);
                            } else {
                                $event_tag_objects[$et['EventTag']['event_id']][] = $et['EventTag'];
                            }
                        }
                    }
                    $eventTags = array_values($eventTags);
                    for ($j = 0; $j < $elements; $j++) {
                        if (!empty($event_tag_objects[$events[($i*1000) + $j]['Event']['id']])) {
                            $events[($i*1000) + $j]['EventTag'] = $event_tag_objects[$events[($i*1000) + $j]['Event']['id']];
                        } else {
                            $events[($i*1000) + $j]['EventTag'] = array();
                        }
                    }
                }
                $events = $this->GalaxyCluster->attachClustersToEventIndex($events);
                foreach ($events as $key => $event) {
                    $temp = $events[$key]['Event'];
                    $temp['Org'] = $event['Org'];
                    $temp['Orgc'] = $event['Orgc'];
                    unset($temp['user_id']);
                    $rearrangeObjects = array('GalaxyCluster', 'EventTag', 'SharingGroup');
                    foreach ($rearrangeObjects as $ro) {
                        if (isset($event[$ro])) {
                            $temp[$ro] = $event[$ro];
                        }
                    }
                    $events[$key] = $temp;
                }
                if ($this->response->type() === 'application/xml') {
                    $events = array('Event' => $events);
                }
                return $this->RestResponse->viewData($events, $this->response->type(), false, false, false, array('X-Result-Count' => $absolute_total));
            } else {
                foreach ($events as $key => $event) {
                    $event['Event']['orgc_uuid'] = $event['Orgc']['uuid'];
                    $events[$key] = $event['Event'];
                }
                return $this->RestResponse->viewData($events, $this->response->type(), false, false, false, array('X-Result-Count' => $absolute_total));
            }
        } else {
            $events = $this->paginate();
            foreach ($events as $k => $event) {
                if (empty($event['SharingGroup']['name'])) {
                    unset($events[$k]['SharingGroup']);
                }
            }
            if (count($events) == 1 && isset($this->passedArgs['searchall'])) {
                $this->redirect(array('controller' => 'events', 'action' => 'view', $events[0]['Event']['id']));
            }
            $events = $this->Event->attachTagsToEvents($events);
            if (Configure::read('MISP.showCorrelationsOnIndex')) {
                $events = $this->Event->attachCorrelationCountToEvents($this->Auth->user(), $events);
            }
            if (Configure::read('MISP.showSightingsCountOnIndex')) {
                $events = $this->Event->attachSightingsCountToEvents($this->Auth->user(), $events);
            }
            if (Configure::read('MISP.showProposalsCountOnIndex')) {
                $events = $this->Event->attachProposalsCountToEvents($this->Auth->user(), $events);
            }
            if (Configure::read('MISP.showDiscussionsCountOnIndex')) {
                $events = $this->Event->attachDiscussionsCountToEvents($this->Auth->user(), $events);
            }
            $events = $this->GalaxyCluster->attachClustersToEventIndex($events, true);
            $this->set('events', $events);
        }

        if (!$this->Event->User->getPGP($this->Auth->user('id')) && Configure::read('GnuPG.onlyencrypted')) {
            // No GnuPG
            if (Configure::read('SMIME.enabled') && !$this->Event->User->getCertificate($this->Auth->user('id'))) {
                // No GnuPG and No SMIME
                $this->Flash->info(__('No x509 certificate or GnuPG key set in your profile. To receive emails, submit your public certificate or GnuPG key in your profile.'));
            } elseif (!Configure::read('SMIME.enabled')) {
                $this->Flash->info(__('No GnuPG key set in your profile. To receive emails, submit your public key in your profile.'));
            }
        } elseif ($this->Auth->user('autoalert') && !$this->Event->User->getPGP($this->Auth->user('id')) && Configure::read('GnuPG.bodyonlyencrypted')) {
            // No GnuPG & autoalert
            if ($this->Auth->user('autoalert') && Configure::read('SMIME.enabled') && !$this->Event->User->getCertificate($this->Auth->user('id'))) {
                // No GnuPG and No SMIME & autoalert
                $this->Flash->info(__('No x509 certificate or GnuPG key set in your profile. To receive attributes in emails, submit your public certificate or GnuPG key in your profile.'));
            } elseif (!Configure::read('SMIME.enabled')) {
                $this->Flash->info(__('No GnuPG key set in your profile. To receive attributes in emails, submit your public key in your profile.'));
            }
        }
        $this->set('eventDescriptions', $this->Event->fieldDescriptions);
        $this->set('analysisLevels', $this->Event->analysisLevels);
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->set('shortDist', $this->Event->shortDist);
        $this->set('distributionData', $this->genDistributionGraph(-1));
        if ($this->params['ext'] === 'csv') {
            App::uses('CsvExport', 'Export');
            $export = new CsvExport();
            return $this->RestResponse->viewData($export->eventIndex($events), 'csv');
        }
        if ($this->request->is('ajax')) {
            $this->autoRender = false;
            $this->layout = false;
            $this->render('ajax/index');
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
            'threatlevel' => array('OR' => array(), 'NOT' => array()),
            'distribution' => array('OR' => array(), 'NOT' => array()),
            'sharinggroup' => array('OR' => array(), 'NOT' => array()),
            'analysis' => array('OR' => array(), 'NOT' => array()),
            'attribute' => array('OR' => array(), 'NOT' => array()),
            'hasproposal' => 2,
        );

        if ($this->_isSiteAdmin()) {
            $filtering['email'] = array('OR' => array(), 'NOT' => array());
        }

        foreach ($this->passedArgs as $k => $v) {
            if (substr($k, 0, 6) === 'search') {
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
        $tags = $this->Event->EventTag->Tag->find('all', array('recursive' => -1));
        $tagNames = array();
        $tagJSON = array();
        foreach ($tags as $k => $v) {
            $tagNames[$v['Tag']['id']] = $v['Tag']['name'];
            $tagJSON[] = array('id' => $v['Tag']['id'], 'value' => h($v['Tag']['name']));
        }
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $eIds = $this->Event->fetchEventIds($this->Auth->user(), false, false, false, true);
            $conditions['AND'][] = array('Event.id' => $eIds);
        }
        $rules = array('published', 'eventid', 'tag', 'date', 'eventinfo', 'threatlevel', 'distribution', 'sharinggroup', 'analysis', 'attribute', 'hasproposal');
        if ($this->_isSiteAdmin()) {
            $rules[] = 'email';
        }
        if (Configure::read('MISP.showorg')) {
            $orgs = $this->Event->Orgc->find('list', array(
                'conditions' => array(),
                'recursive' => -1,
                'fields' => array('Orgc.id', 'Orgc.name'),
                'sort' => array('lower(Orgc.name) asc')
            ));
            $this->set('showorg', true);
            $this->set('orgs', $orgs);
            $rules[] = 'org';
        } else {
            $this->set('showorg', false);
        }
        $sharingGroups = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', true);
        $this->set('sharingGroups', $sharingGroups);
        $rules = $this->_arrayToValuesIndexArray($rules);
        $this->set('tags', $tagNames);
        $this->set('tagJSON', json_encode($tagJSON));
        $this->set('rules', $rules);
        $this->set('baseurl', Configure::read('MISP.baseurl'));
        $this->layout = 'ajax';
    }

    /*
     * Search for a value on an attribute level for a specific field.
     * $attribute : (array) an attribute
     * $fields : (array) list of keys in attribute to search in
     * $searchValue : Values to search ( '|' is the separator)
     * returns true on match
     */
    private function __valueInFieldAttribute($attribute, $fields, $searchValue)
    {
        foreach ($attribute as $k => $v) { // look in attributes line
            if (is_string($v)) {
                foreach ($fields as $field) {
                    if (strpos(".", $field) === false) { // check sub array after
                        // check for key in attribut
                        if (isset($attribute[$field])) {
                            $temp_value = strtolower($attribute[$field]);
                            $temp_search = strtolower($searchValue);
                            $temp_searches = explode('|', $temp_search);
                            foreach ($temp_searches as $s) {
                                if (strpos($temp_value, $s) !==false) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            } else {
                // check for tag in attribut maybe for other thing later
                if ($k === 'AttributeTag') {
                    foreach ($v as $tag) {
                        foreach ($fields as $field) {
                            if (strpos(strtolower($field), "tag.") !== false) { // check sub array
                                $tagKey = explode('tag.', strtolower($field))[1];
                                if (isset($tag['Tag'][$tagKey])) {
                                    $temp_value = strtolower($tag['Tag'][$tagKey]);
                                    $temp_search = strtolower($searchValue);
                                    if (strpos($temp_value, $temp_search) !==false) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public function viewEventAttributes($id, $all = false)
    {
        $filterData = array(
            'request' => $this->request,
            'paramArray' => $this->acceptedFilteringNamedParams,
            'named_params' => $this->params['named']
        );
        $exception = false;
        $filters = $this->_harvestParameters($filterData, $exception);

        if (isset($filters['focus'])) {
            $this->set('focus', $filters['focus']);
        }
        $conditions = array('eventid' => $id);
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
            $conditions['deleted'] = $filters['deleted'] == 2 ? 0 : [0, 1];
            if ($filters['deleted'] == 2) { // not-deleted only
                $conditions['deleted'] = 0;
            } elseif ($filters['deleted'] == 1) { // deleted only
                $conditions['deleted'] = 1;
            } else { // both
                $conditions['deleted'] = [0, 1];
            }
        }
        if (isset($filters['toIDS']) && $filters['toIDS'] != 0) {
            $conditions['to_ids'] = $filters['toIDS'] == 2 ? 0 : 1;
        }
        $conditions['includeFeedCorrelations'] = true;
        if (!isset($filters['includeServerCorrelations'])) {
            $conditions['includeServerCorrelations'] = 1;
            if ($this->_isRest()) {
                $conditions['includeServerCorrelations'] = 0;
            }
        } else {
            $conditions['includeServerCorrelations'] = $filters['includeServerCorrelations'];
        }
        $conditions['includeAllTags'] = true;
        $conditions['includeGranularCorrelations'] = 1;
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

        $results = $this->Event->fetchEvent($this->Auth->user(), $conditions);
        if (empty($results)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $event = $results[0];

        $attributeTagsName = $this->Event->Attribute->AttributeTag->extractAttributeTagsNameFromEvent($event, 'both');
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
        $emptyEvent = (empty($event['Object']) && empty($event['Attribute']));
        $this->set('emptyEvent', $emptyEvent);

        // remove galaxies tags
        $this->loadModel('GalaxyCluster');
        $this->loadModel('Taxonomy');
        $cluster_names = $this->GalaxyCluster->find('list', array('fields' => array('GalaxyCluster.tag_name'), 'group' => array('GalaxyCluster.tag_name', 'GalaxyCluster.id')));
        foreach ($event['Object'] as $k => $object) {
            if (isset($object['Attribute'])) {
                foreach ($object['Attribute'] as $k2 => $attribute) {
                    foreach ($attribute['AttributeTag'] as $k3 => $attributeTag) {
                        if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
                            unset($event['Object'][$k]['Attribute'][$k2]['AttributeTag'][$k3]);
                        }
                    }
                    $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
                    foreach ($tagConflicts['global'] as $tagConflict) {
                        $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                    }
                    foreach ($tagConflicts['local'] as $tagConflict) {
                        $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                    }
                    $event['Object'][$k]['Attribute'][$k2]['tagConflicts'] = $tagConflicts;
                }
            }
        }
        foreach ($event['Attribute'] as $k => $attribute) {
            foreach ($attribute['AttributeTag'] as $k2 => $attributeTag) {
                if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
                    unset($event['Attribute'][$k]['AttributeTag'][$k2]);
                }
            }
            $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
            foreach ($tagConflicts['global'] as $tagConflict) {
                $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
            }
            foreach ($tagConflicts['local'] as $tagConflict) {
                $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
            }
            $event['Attribute'][$k]['tagConflicts'] = $tagConflicts;
        }
        if (empty($this->passedArgs['sort'])) {
            $filters['sort'] = 'timestamp';
            $filters['direction'] = 'desc';
        }
        $sightingsData = $this->Event->getSightingData($event);
        $this->set('sightingsData', $sightingsData);
        $params = $this->Event->rearrangeEventForView($event, $filters, $all, $sightingsData);
        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->loadModel('Sightingdb');
            $event = $this->Sightingdb->attachToEvent($event, $this->Auth->user());
        }
        $this->params->params['paging'] = array($this->modelClass => $params);
        // workaround to get the event dates in to the attribute relations
        $relatedDates = array();
        if (isset($event['RelatedEvent'])) {
            foreach ($event['RelatedEvent'] as $relation) {
                $relatedDates[$relation['Event']['id']] = $relation['Event']['date'];
            }
            if (isset($event['RelatedAttribute'])) {
                foreach ($event['RelatedAttribute'] as $key => $relatedAttribute) {
                    foreach ($relatedAttribute as $key2 => $relation) {
                        $event['RelatedAttribute'][$key][$key2]['date'] = $relatedDates[$relation['id']];
                    }
                }
            }
        }
        $this->set('event', $event);
        $dataForView = array(
                'Attribute' => array('attrDescriptions', 'typeDefinitions', 'categoryDefinitions', 'distributionDescriptions', 'distributionLevels', 'shortDist'),
                'Event' => array('fieldDescriptions')
        );
        foreach ($dataForView as $m => $variables) {
            if ($m === 'Event') {
                $currentModel = $this->Event;
            } elseif ($m === 'Attribute') {
                $currentModel = $this->Event->Attribute;
            }
            foreach ($variables as $variable) {
                $this->set($variable, $currentModel->{$variable});
            }
        }
        if (Configure::read('Plugin.Enrichment_services_enable')) {
            $this->loadModel('Module');
            $modules = $this->Module->getEnabledModules($this->Auth->user());
            if (!empty($modules) && is_array($modules)) {
                foreach ($modules as $k => $v) {
                    if (isset($v['restrict'])) {
                        if (!$this->_isSiteAdmin() && $v['restrict'] != $this->Auth->user('org_id')) {
                            unset($modules[$k]);
                        }
                    }
                }
            }
            $this->set('modules', $modules);
        }
        if (Configure::read('Plugin.Cortex_services_enable')) {
            $this->loadModel('Module');
            $cortex_modules = $this->Module->getEnabledModules($this->Auth->user(), false, 'Cortex');
            $this->set('cortex_modules', $cortex_modules);
        }
        $deleted = 0;
        if (isset($filters['deleted'])) {
            $deleted = $filters['deleted'] == 2 ? 0 : 1;
        }
        $this->set('includeSightingdb', (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')));
        $this->set('deleted', $deleted);
        $this->set('typeGroups', array_keys($this->Event->Attribute->typeGroupings));
        $this->set('attributeFilter', isset($filters['attributeFilter']) ? $filters['attributeFilter'] : 'all');
        $this->set('filters', $filters);
        $advancedFiltering = $this->__checkIfAdvancedFiltering($filters);
        $this->set('advancedFilteringActive', $advancedFiltering['active'] ? 1 : 0);
        $this->set('advancedFilteringActiveRules', $advancedFiltering['activeRules']);
        $this->set('defaultFilteringRules', $this->defaultFilteringRules);
        $this->disableCache();
        $this->layout = 'ajax';
        $this->loadModel('Sighting');
        $uriArray = explode('/', $this->params->here);
        foreach ($uriArray as $k => $v) {
            if (strpos($v, ':')) {
                $temp = explode(':', $v);
                if ($temp[0] == 'focus') {
                    unset($uriArray[$k]);
                }
            }
            $this->params->here = implode('/', $uriArray);
        }
        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->set('sightingdbs', $this->Sightingdb->getSightingdbList($this->Auth->user()));
        }
        $this->set('sightingTypes', $this->Sighting->type);
        $this->set('currentUri', $this->params->here);
        $this->layout = false;
        $this->render('/Elements/eventattribute');
    }

    private function __viewUI($event, $continue, $fromEvent)
    {
        $this->loadModel('Taxonomy');
        $filterData = array(
            'request' => $this->request,
            'paramArray' => $this->acceptedFilteringNamedParams,
            'named_params' => $this->params['named']
        );
        $exception = false;
        $warningTagConflicts = array();
        $filters = $this->_harvestParameters($filterData, $exception);

        $this->loadModel('GalaxyCluster');
        if (!$this->_isRest()) {
            //$attack = $this->GalaxyCluster->Galaxy->constructAttackReport($event);
        }
        $emptyEvent = (empty($event['Object']) && empty($event['Attribute']));
        $this->set('emptyEvent', $emptyEvent);
        $attributeCount = isset($event['Attribute']) ? count($event['Attribute']) : 0;
        $objectCount = isset($event['Object']) ? count($event['Object']) : 0;
        $oldest_timestamp = false;
        if (!empty($event['Object'])) {
            foreach ($event['Object'] as $k => $object) {
                if (!empty($object['Attribute'])) {
                    foreach ($object['Attribute'] as $attribute) {
                        if ($oldest_timestamp == false || $oldest_timestamp > $attribute['timestamp']) {
                            $oldest_timestamp = $attribute['timestamp'];
                        }
                    }
                    $attributeCount += count($object['Attribute']);
                }
            }
        }
        $this->set('attribute_count', $attributeCount);
        $this->set('object_count', $objectCount);
        // set the data for the contributors / history field
        $contributors = $this->Event->ShadowAttribute->getEventContributors($event['Event']['id']);
        if ($this->userRole['perm_publish'] && $event['Event']['orgc_id'] == $this->Auth->user('org_id')) {
            $proposalStatus = false;
            if (isset($event['ShadowAttribute']) && !empty($event['ShadowAttribute'])) {
                $proposalStatus = true;
            }
            if (!$proposalStatus && !empty($event['Attribute'])) {
                foreach ($event['Attribute'] as $temp) {
                    if (isset($temp['ShadowAttribute']) && !empty($temp['ShadowAttribute'])) {
                        $proposalStatus = true;
                    }
                }
            }
            $mess = $this->Session->read('Message');
            if ($proposalStatus && empty($mess)) {
                $this->Flash->info('This event has active proposals for you to accept or discard.');
            }
        }
        // set the pivot data
        $this->helpers[] = 'Pivot';
        if ($continue) {
            $data = $this->__continuePivoting($event['Event']['id'], $event['Event']['info'], $event['Event']['date'], $fromEvent);
        } else {
            $data = $this->__startPivoting($event['Event']['id'], $event['Event']['info'], $event['Event']['date']);
        }
        $pivot = $this->Session->read('pivot_thread');
        $this->__arrangePivotVertical($pivot);
        $this->__setDeletable($pivot, $event['Event']['id'], true);
        $this->set('allPivots', $this->Session->read('pivot_thread'));
        $this->set('pivot', $pivot);
        // set data for the view, the event is already set in view()
        $dataForView = array(
                'Attribute' => array('attrDescriptions' => 'fieldDescriptions', 'distributionDescriptions' => 'distributionDescriptions', 'distributionLevels' => 'distributionLevels', 'shortDist' => 'shortDist'),
                'Event' => array('eventDescriptions' => 'fieldDescriptions', 'analysisDescriptions' => 'analysisDescriptions', 'analysisLevels' => 'analysisLevels')
        );

        // workaround to get the event dates in to the attribute relations and number of correlation per related event
        $relatedDates = array();
        $relatedEventCorrelationCount = array();
        if (!empty($event['RelatedEvent'])) {
            foreach ($event['RelatedEvent'] as $relation) {
                $relatedDates[$relation['Event']['id']] = $relation['Event']['date'];
            }
            if (!empty($event['RelatedAttribute'])) {
                foreach ($event['RelatedAttribute'] as $key => $relatedAttribute) {
                    foreach ($relatedAttribute as $key2 => $relation) {
                        if (!empty($relatedDates[$relation['id']])) {
                            $event['RelatedAttribute'][$key][$key2]['date'] = $relatedDates[$relation['id']];
                        }
                        $relatedEventCorrelationCount[$relation['id']][$relation['value']] = 1;
                    }
                }
            }
        }
        foreach ($relatedEventCorrelationCount as $key => $relation) {
            $relatedEventCorrelationCount[$key] = count($relatedEventCorrelationCount[$key]);
        }

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
        $cluster_names = $this->GalaxyCluster->find('list', array('fields' => array('GalaxyCluster.tag_name'), 'group' => array('GalaxyCluster.tag_name', 'GalaxyCluster.id')));
        foreach ($event['EventTag'] as $k => $eventTag) {
            if (in_array($eventTag['Tag']['name'], $cluster_names)) {
                unset($event['EventTag'][$k]);
            }
        }

        $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($event['EventTag']);
        foreach ($tagConflicts['global'] as $tagConflict) {
            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
        }
        foreach ($tagConflicts['local'] as $tagConflict) {
            $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
        }
        $this->set('tagConflicts', $tagConflicts);

        $startDate = null;
        $modificationMap = array();
        foreach ($event['Attribute'] as $k => $attribute) {
            if ($oldest_timestamp == false || $oldest_timestamp > $attribute['timestamp']) {
                $oldest_timestamp = $attribute['timestamp'];
            }
            if ($startDate === null || $attribute['timestamp'] < $startDate) {
                $startDate = $attribute['timestamp'];
            }
            $modDate = date("Y-m-d", $attribute['timestamp']);
            $modificationMap[$modDate] = empty($modificationMap[$modDate])? 1 : $modificationMap[date("Y-m-d", $attribute['timestamp'])] + 1;
            foreach ($attribute['AttributeTag'] as $k2 => $attributeTag) {
                if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
                    unset($event['Attribute'][$k]['AttributeTag'][$k2]);
                }
            }
            $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
            foreach ($tagConflicts['global'] as $tagConflict) {
                $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
            }
            foreach ($tagConflicts['local'] as $tagConflict) {
                $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
            }
            $event['Attribute'][$k]['tagConflicts'] = $tagConflicts;
        }
        $attributeTagsName = $this->Event->Attribute->AttributeTag->extractAttributeTagsNameFromEvent($event, 'both');
        $this->set('attributeTags', array_values($attributeTagsName['tags']));
        $this->set('attributeClusters', array_values($attributeTagsName['clusters']));
        $startDate = $event['Event']['timestamp'];
        $modDate = date("Y-m-d", $event['Event']['timestamp']);
        $modificationMap[$modDate] = 1;
        foreach ($event['Object'] as $k => $object) {
            if ($startDate === null || $object['timestamp'] < $startDate) {
                $startDate = $object['timestamp'];
            }
            $modDate = date("Y-m-d", $object['timestamp']);
            $modificationMap[$modDate] = empty($modificationMap[$modDate])? 1 : $modificationMap[date("Y-m-d", $object['timestamp'])] + 1;
            if (!empty($object['Attribute'])) {
                foreach ($object['Attribute'] as $k2 => $attribute) {
                    if ($startDate === null || $attribute['timestamp'] < $startDate) {
                        $startDate = $attribute['timestamp'];
                    }
                    $modDate = date("Y-m-d", $attribute['timestamp']);
                    $modificationMap[$modDate] = empty($modificationMap[$modDate])? 1 : $modificationMap[date("Y-m-d", $attribute['timestamp'])] + 1;
                    foreach ($attribute['AttributeTag'] as $k3 => $attributeTag) {
                        if (in_array($attributeTag['Tag']['name'], $cluster_names)) {
                            unset($event['Object'][$k]['Attribute'][$k2]['AttributeTag'][$k3]);
                        }
                    }
                    $tagConflicts = $this->Taxonomy->checkIfTagInconsistencies($attribute['AttributeTag']);
                    foreach ($tagConflicts['global'] as $tagConflict) {
                        $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                    }
                    foreach ($tagConflicts['local'] as $tagConflict) {
                        $warningTagConflicts[$tagConflict['taxonomy']['Taxonomy']['namespace']] = $tagConflict['taxonomy'];
                    }
                    $event['Object'][$k]['Attribute'][$k2]['tagConflicts'] = $tagConflicts;
                }
            }
        }
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
        $to = date('Y-m-d', time());
        if ((strtotime($to) - 172800) > $startDate) {
            $startDate = date('Y-m-d', strtotime($to) - 172800);
        }
        for ($date = $startDate; strtotime($date) <= strtotime($to); $date = date('Y-m-d', strtotime("+1 day", strtotime($date)))) {
            if (isset($modificationMap[$date])) {
                $modificationMapCSV .= $date . ',' . $modificationMap[$date] . '\n';
            } else {
                $modificationMapCSV .= $date . ',0\n';
            }
        }
        unset($modificationMap);
        $sightingsData = $this->Event->getSightingData($event);
        $this->set('sightingsData', $sightingsData);
        $params = $this->Event->rearrangeEventForView($event, $filters, false, $sightingsData);
        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->loadModel('Sightingdb');
            $event = $this->Sightingdb->attachToEvent($event, $this->Auth->user());
        }
        $this->params->params['paging'] = array($this->modelClass => $params);
        $this->set('event', $event);
        $dataForView = array(
                'Attribute' => array('attrDescriptions', 'typeDefinitions', 'categoryDefinitions', 'distributionDescriptions', 'distributionLevels'),
                'Event' => array('fieldDescriptions')
        );
        foreach ($dataForView as $m => $variables) {
            if ($m === 'Event') {
                $currentModel = $this->Event;
            } elseif ($m === 'Attribute') {
                $currentModel = $this->Event->Attribute;
            }
            foreach ($variables as $variable) {
                $this->set($variable, $currentModel->{$variable});
            }
        }
        $extensionParams = array(
            'conditions' => array(
                'Event.extends_uuid' => $event['Event']['uuid']
            )
        );
        $extensions = $this->Event->fetchSimpleEvents($this->Auth->user(), $extensionParams);
        $this->set('extensions', $extensions);
        if (!empty($event['Event']['extends_uuid'])) {
            $extendedEvent = $this->Event->fetchSimpleEvents($this->Auth->user(), array('conditions' => array('Event.uuid' => $event['Event']['extends_uuid'])));
            if (empty($extendedEvent)) {
                $extendedEvent = $event['Event']['extends_uuid'];
            }
            $this->set('extendedEvent', $extendedEvent);
        }
        if (Configure::read('MISP.delegation')) {
            $this->loadModel('EventDelegation');
            $delegationConditions = array('EventDelegation.event_id' => $event['Event']['id']);
            if (!$this->_isSiteAdmin() && $this->userRole['perm_publish']) {
                $delegationConditions['OR'] = array('EventDelegation.org_id' => $this->Auth->user('org_id'),
                                                    'EventDelegation.requester_org_id' => $this->Auth->user('org_id'));
            }
            $this->set('delegationRequest', $this->EventDelegation->find('first', array(
                'conditions' => $delegationConditions,
                'recursive' => -1,
                'contain' => array('Org', 'RequesterOrg')
            )));
        }
        if (Configure::read('Plugin.Enrichment_services_enable')) {
            $this->loadModel('Module');
            $modules = $this->Module->getEnabledModules($this->Auth->user());
            if (is_array($modules)) {
                foreach ($modules as $k => $v) {
                    if (isset($v['restrict'])) {
                        if ($this->_isSiteAdmin() && $v['restrict'] != $this->Auth->user('org_id')) {
                            unset($modules[$k]);
                        }
                    }
                }
            }
            $this->set('modules', $modules);
        }
        if (Configure::read('Plugin.Cortex_services_enable')) {
            $this->loadModel('Module');
            $cortex_modules = $this->Module->getEnabledModules($this->Auth->user(), false, 'Cortex');
            $this->set('cortex_modules', $cortex_modules);
        }
        $this->set('contributors', $contributors);
        $this->set('typeGroups', array_keys($this->Event->Attribute->typeGroupings));
        $this->loadModel('Sighting');
        $this->set('sightingTypes', $this->Sighting->type);
        $attributeUri = '/events/viewEventAttributes/' . $event['Event']['id'];
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
        $orgTable = $this->Event->Orgc->find('list', array(
            'fields' => array('Orgc.id', 'Orgc.name')
        ));
        if (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')) {
            $this->set('sightingdbs', $this->Sightingdb->getSightingdbList($this->Auth->user()));
        }
        $this->set('includeSightingdb', (!empty($filters['includeSightingdb']) && Configure::read('Plugin.Sightings_sighting_db_enable')));
        $this->set('relatedEventCorrelationCount', $relatedEventCorrelationCount);
        $this->set('oldest_timestamp', $oldest_timestamp);
        $this->set('required_taxonomies', $this->Event->getRequiredTaxonomies());
        $this->set('orgTable', $orgTable);
        $this->set('currentUri', $attributeUri);
        $this->set('filters', $filters);
        $advancedFiltering = $this->__checkIfAdvancedFiltering($filters);
        $this->set('advancedFilteringActive', $advancedFiltering['active'] ? 1 : 0);
        $this->set('advancedFilteringActiveRules', $advancedFiltering['activeRules']);
        $this->set('defaultFilteringRules', $this->defaultFilteringRules);
        $this->set('mitreAttackGalaxyId', $this->Event->GalaxyCluster->Galaxy->getMitreAttackGalaxyId());
        $this->set('modificationMapCSV', $modificationMapCSV);
    }

    public function view($id = null, $continue=false, $fromEvent=null)
    {
        // find the id of the event, change $id to it and proceed to read the event as if the ID was entered.
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        $this->Event->id = $id;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid event'));
        }
        $conditions = array('eventid' => $id);
        if (!$this->_isRest()) {
            $conditions['includeAllTags'] = true;
        } else {
            $conditions['includeAttachments'] = true;
        }
        $deleted = 0;
        if (isset($this->params['named']['deleted'])) {
            $deleted = $this->params['named']['deleted'];
        }
        if (isset($this->request->data['deleted'])) {
            $deleted = $this->request->data['deleted'];
        }
        if (isset($deleted)) {
            // workaround for old instances trying to pull events with both deleted / non deleted data
            if (($this->userRole['perm_sync'] && $this->_isRest() && !$this->userRole['perm_site_admin']) && $deleted == 1) {
                $conditions['deleted'] = array(0,1);
            } else {
                $conditions['deleted'] = $deleted == 2 ? array(0,1) : $deleted;
            }
        }
        if (isset($this->params['named']['toIDS']) && $this->params['named']['toIDS'] != 0) {
            $conditions['to_ids'] = $this->params['named']['toIDS'] == 2 ? 0 : 1;
        }
        if (isset($this->params['named']['includeRelatedTags']) && $this->params['named']['includeRelatedTags']) {
            $conditions['includeRelatedTags'] = 1;
        }
        if (!empty($this->params['named']['includeDecayScore'])) {
            $conditions['includeDecayScore'] = 1;
        }
        if (isset($this->params['named']['public']) && $this->params['named']['public']) {
            $conditions['distribution'] = array(3, 5);
        }
        if (!empty($this->params['named']['overrideLimit']) && !$this->_isRest()) {
            $conditions['overrideLimit'] = 1;
        }
        if (!empty($this->params['named']['excludeGalaxy'])) {
            $conditions['excludeGalaxy'] = 1;
        }
        if (!empty($this->params['named']['extended'])) {
            $conditions['extended'] = 1;
            $this->set('extended', 1);
        } else {
            $this->set('extended', 0);
        }
        $conditions['includeFeedCorrelations'] = 1;
        if (!$this->_isRest()) {
            $conditions['includeGranularCorrelations'] = 1;
        } else if (!empty($this->params['named']['includeGranularCorrelations'])) {
            $conditions['includeGranularCorrelations'] = 1;
        }
        if (!isset($this->params['named']['includeServerCorrelations'])) {
            $conditions['includeServerCorrelations'] = 1;
            if ($this->_isRest()) {
                $conditions['includeServerCorrelations'] = 0;
            }
        } else {
            $conditions['includeServerCorrelations'] = $this->params['named']['includeServerCorrelations'];
        }
        $results = $this->Event->fetchEvent($this->Auth->user(), $conditions);
        if (!empty($this->params['named']['includeGranularCorrelations'])) {
            foreach ($results as $k => $event) {
                if (!empty($event['RelatedAttribute'])) {
                    foreach ($event['RelatedAttribute'] as $attribute_id => $relation) {
                        foreach ($event['Attribute'] as $k2 => $attribute) {
                            if ((int)$attribute['id'] == $attribute_id) {
                                $results[$k]['Attribute'][$k2]['RelatedAttribute'][] = $relation;
                                break 2;
                            }
                        }
                        foreach ($event['Object'] as $k2 => $object) {
                            foreach ($object['Attribute'] as $k3 => $attribute) {
                                if ((int)$attribute['id'] == $attribute_id) {
                                    $results[$k]['Object'][$k2]['Attribute'][$k3]['RelatedAttribute'][] = $relation;
                                    break 3;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (empty($results)) {
            throw new NotFoundException(__('Invalid event'));
        }
        //if the current user is an org admin AND event belongs to his/her org, fetch also the event creator info
        if ($this->userRole['perm_admin'] && !$this->_isSiteAdmin() && ($results[0]['Org']['id'] == $this->Auth->user('org_id'))) {
            $results[0]['User']['email'] = $this->User->field('email', array('id' => $results[0]['Event']['user_id']));
        }
        $event = $results[0];
        if (isset($this->params['named']['searchFor']) && $this->params['named']['searchFor'] !== '') {
            $this->__applyQueryString($event, $this->params['named']['searchFor']);
        }
        if (isset($this->params['named']['taggedAttributes']) && $this->params['named']['taggedAttributes'] !== '') {
            $this->__applyQueryString($event, $this->params['named']['taggedAttributes'], 'Tag.name');
        }
        if (isset($this->params['named']['galaxyAttachedAttributes']) && $this->params['named']['galaxyAttachedAttributes'] !== '') {
            $this->__applyQueryString($event, $this->params['named']['galaxyAttachedAttributes'], 'Tag.name');
        }

        if ($this->_isRest()) {
            $this->set('event', $event);
        }
        $this->set('deleted', isset($deleted) ? ($deleted == 2 ? 0 : 1) : 0);
        $this->set('includeRelatedTags', (!empty($this->params['named']['includeRelatedTags'])) ? 1 : 0);
        $this->set('includeDecayScore', (!empty($this->params['named']['includeDecayScore'])) ? 1 : 0);
        if (!$this->_isRest()) {
            if ($this->_isSiteAdmin() && $results[0]['Event']['orgc_id'] !== $this->Auth->user('org_id')) {
                $this->Flash->info(__('You are currently logged in as a site administrator and editing an event not belonging to your organisation, which goes against the sharing model of MISP. Please only use this as a last resort and use normal user account for day to day work.'));
            }
            $this->__viewUI($event, $continue, $fromEvent);
        }
    }

    private function __startPivoting($id, $info, $date)
    {
        $this->Session->write('pivot_thread', null);
        $initial_pivot = array('id' => $id, 'info' => $info, 'date' => $date, 'depth' => 0, 'height' => 0, 'children' => array(), 'deletable' => true);
        $this->Session->write('pivot_thread', $initial_pivot);
    }

    private function __continuePivoting($id, $info, $date, $fromEvent)
    {
        $pivot = $this->Session->read('pivot_thread');
        $newPivot = array('id' => $id, 'info' => $info, 'date' => $date, 'depth' => null, 'children' => array(), 'deletable' => true);
        if (!$this->__checkForPivot($pivot, $id)) {
            $pivot = $this->__insertPivot($pivot, $fromEvent, $newPivot, 0);
        }
        $this->Session->write('pivot_thread', $pivot);
    }

    private function __insertPivot($pivot, $oldId, $newPivot, $depth)
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

    private function __checkForPivot($pivot, $id)
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

    private function __applyQueryString(&$event, $searchFor, $filterColumnsOverwrite=false) {
        // filtering on specific columns is specified
        if ($filterColumnsOverwrite !== false) {
            $filterValue = array_map('trim', explode(",", $filterColumnsOverwrite));
        } else {
            $filterColumnsOverwrite = empty(Configure::read('MISP.event_view_filter_fields')) ? 'id, uuid, value, comment, type, category, Tag.name' : Configure::read('MISP.event_view_filter_fields');
            $filterValue = array_map('trim', explode(",", $filterColumnsOverwrite));
            $validFilters = array('id', 'uuid', 'value', 'comment', 'type', 'category', 'Tag.name');
            foreach ($filterValue as $k => $v) {
                if (!in_array($v, $validFilters)) {
                    unset($filterValue[$k]);
                }
            }
        }

        // search in all attributes
        foreach ($event['Attribute'] as $k => $attribute) {
            if (!$this->__valueInFieldAttribute($attribute, $filterValue, $searchFor)) {
                unset($event['Attribute'][$k]);
            }
        }
        $event['Attribute'] = array_values($event['Attribute']);

        // search in all attributes
        foreach ($event['ShadowAttribute'] as $k => $proposals) {
            if (!$this->__valueInFieldAttribute($proposals, $filterValue, $searchFor)) {
                unset($event['ShadowAttribute'][$k]);
            }
        }
        $event['ShadowAttribute'] = array_values($event['ShadowAttribute']);

        // search for all attributes in object
        foreach ($event['Object'] as $k => $object) {
            foreach ($object['Attribute'] as $k2 => $attribute) {
                if (!$this->__valueInFieldAttribute($attribute, $filterValue, $searchFor)) {
                    unset($event['Object'][$k]['Attribute'][$k2]);
                }
            }
            if (count($event['Object'][$k]['Attribute']) == 0) {
                // remove object if empty
                unset($event['Object'][$k]);
            } else {
                $event['Object'][$k]['Attribute'] = array_values($event['Object'][$k]['Attribute']);
            }
        }
        $event['Object'] = array_values($event['Object']);
    }

    // look in the parameters if we are doing advanced filtering or not
    private function __checkIfAdvancedFiltering($filters) {
        $advancedFilteringActive = array_diff_key($filters, array('sort'=>0, 'direction'=>0, 'focus'=>0, 'extended'=>0, 'overrideLimit'=>0, 'filterColumnsOverwrite'=>0, 'attributeFilter'=>0, 'extended' => 0, 'page' => 0));

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
            if (isset($this->defaultFilteringRules[$k]) && $this->defaultFilteringRules[$k] != $v) {
                $activeRules[$k] = 1;
            }
        }
        return array('active' => $activeRules > 0 ? $res : false, 'activeRules' => $activeRules);
    }

    private function __removeChildren(&$pivot, $id)
    {
        if ($pivot['id'] == $id) {
            $pivot['children'] = array();
        } else {
            foreach ($pivot['children'] as $k => $v) {
                $this->__removeChildren($v, $id);
            }
        }
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
        if (!$this->userRole['perm_add']) {
            throw new MethodNotAllowedException(__('You don\'t have permissions to create events'));
        }
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
            if (!empty($this->data)) {
                if (!isset($this->request->data['Event']['distribution'])) {
                    $this->request->data['Event']['distribution'] = Configure::read('MISP.default_event_distribution') ? Configure::read('MISP.default_event_distribution') : 0;
                }
                if (!isset($this->request->data['Event']['analysis'])) {
                    $this->request->data['Event']['analysis'] = 0;
                }
                if (!isset($this->request->data['Event']['threat_level_id'])) {
                    $this->request->data['Event']['threat_level_id'] = Configure::read('MISP.default_event_threat_level') ? Configure::read('MISP.default_event_threat_level') : 4;
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
                if ($add === true && !is_numeric($add)) {
                    if ($this->_isRest()) {
                        if ($add === 'blocked') {
                            throw new ForbiddenException(__('Event blocked by local blacklist.'));
                        }
                        // REST users want to see the newly created event
                        $results = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $created_id));
                        $event = $results[0];
                        if (!empty($validationErrors)) {
                            $event['errors'] = $validationErrors;
                        }
                        $this->set('event', $event);
                        $this->render('view');
                        return true;
                    } else {
                        // redirect to the view of the newly created event
                        $this->Flash->success(__('The event has been saved'));
                        $this->redirect(array('action' => 'view', $this->Event->getID()));
                    }
                } else {
                    if ($this->_isRest()) { // TODO return error if REST
                        if (is_numeric($add)) {
                            $this->response->header('Location', Configure::read('MISP.baseurl') . '/events/' . $add);
                            $this->response->send();
                            throw new NotFoundException(__('Event already exists, if you would like to edit it, use the url in the location header.'));
                        }
                        // # TODO i18n?
                        return $this->RestResponse->saveFailResponse('Events', 'add', false, $validationErrors, $this->response->type());
                    } else {
                        if ($add === 'blocked') {
                            $this->Flash->error(__('A blacklist entry is blocking you from creating any events. Please contact the administration team of this instance') . (Configure::read('MISP.contact') ? ' at ' . Configure::read('MISP.contact') : '') . '.');
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
        $threat_levels = $this->Event->ThreatLevel->find('all');
        $this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
        $fieldDesc['threat_level_id'] = Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.description');

        // combobox for analysis
        $this->set('sharingGroups', $sgs);
        // tooltip for analysis
        $analysisLevels = $this->Event->analysisLevels;
        $this->set('analysisLevels', $analysisLevels);
        foreach ($analysisLevels as $key => $value) {
            $fieldDesc['analysis'][$key] = $this->Event->analysisDescriptions[$key]['formdesc'];
        }
        if (!$this->_isRest()) {
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
        if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc_id'] != $this->_checkOrg() || !$this->userRole['perm_modify'])) {
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
        $this->set('published', $this->Event->data['Event']['published']);
    }

    public function add_misp_export()
    {
        if (!$this->userRole['perm_modify']) {
            throw new UnauthorizedException(__('You do not have permission to do that.'));
        }
        if ($this->request->is('post')) {
            $results = array();
            if (!empty($this->data)) {
                $ext = '';
                if (isset($this->data['Event']['submittedfile'])) {
                    $ext = pathinfo($this->data['Event']['submittedfile']['name'], PATHINFO_EXTENSION);
                }
                if (isset($this->data['Event']['submittedfile']) && (strtolower($ext) != 'xml' && strtolower($ext) != 'json') && $this->data['Event']['submittedfile']['size'] > 0 &&
                is_uploaded_file($this->data['Event']['submittedfile']['tmp_name'])) {
                    $log = ClassRegistry::init('Log');
                    // #TODO Think about whether we want to Localize Log entries.
                    $log->createLogEntry($this->Auth->user(), 'file_upload', 'Event', 0, 'MISP export file upload failed', 'File details: ' . json_encode($this->data['Event']['submittedfile']));
                    $this->Flash->error(__('You may only upload MISP XML or MISP JSON files.'));
                    throw new MethodNotAllowedException(__('File upload failed or file does not have the expected extension (.xml / .json).'));
                }
                if (isset($this->data['Event']['submittedfile'])) {
                    if (Configure::read('MISP.take_ownership_xml_import')
                        && (isset($this->data['Event']['takeownership']) && $this->data['Event']['takeownership'] == 1)) {
                        $results = $this->_addMISPExportFile($ext, true, $this->data['Event']['publish']);
                    } else {
                        $results = $this->_addMISPExportFile($ext, false, $this->data['Event']['publish']);
                    }
                }
            }
            $this->set('results', $results);
            $this->render('add_misp_export_result');
        }
    }

    public function upload_stix($stix_version = '1')
    {
        if (!$this->userRole['perm_modify']) {
            throw new UnauthorizedException(__('You do not have permission to do that.'));
        }
        if ($this->request->is('post')) {
            if ($this->_isRest()) {
                $randomFileName = $this->Event->generateRandomFileName();
                $tmpDir = APP . "files" . DS . "scripts" . DS . "tmp";
                $tempFile = new File($tmpDir . DS . $randomFileName, true, 0644);
                $tempFile->write($this->request->input());
                $tempFile->close();
                $result = $this->Event->upload_stix(
                    $this->Auth->user(),
                    $randomFileName,
                    $stix_version,
                    'uploaded_stix_file.' . ($stix_version == '1' ? 'xml' : 'json'),
                    false
                );
                if (is_array($result)) {
                    return $this->RestResponse->saveSuccessResponse('Events', 'upload_stix', false, $this->response->type(), 'STIX document imported, event\'s created: ' . implode(', ', $result) . '.');
                } elseif (is_numeric($result)) {
                    $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $result));
                    if (!empty($event)) {
                        return $this->RestResponse->viewData($event[0], 'json');
                    } else {
                        return $this->RestResponse->saveFailResponse('Events', 'upload_stix', false, 'Could not read saved event.', $this->response->type());
                    }
                } else {
                    return $this->RestResponse->saveFailResponse('Events', 'upload_stix', false, $result, $this->response->type());
                }
            } else {
                $original_file = !empty($this->data['Event']['original_file']) ? $this->data['Event']['stix']['name'] : '';
                if (isset($this->data['Event']['stix']) && $this->data['Event']['stix']['size'] > 0 && is_uploaded_file($this->data['Event']['stix']['tmp_name'])) {
                    $randomFileName = $this->Event->generateRandomFileName();
                    $tmpDir = APP . "files" . DS . "scripts" . DS . "tmp";
                    move_uploaded_file($this->data['Event']['stix']['tmp_name'], $tmpDir . DS . $randomFileName);
                    $result = $this->Event->upload_stix(
                        $this->Auth->user(),
                        $randomFileName,
                        $stix_version,
                        $original_file,
                        $this->data['Event']['publish']
                    );
                    if (is_array($result)) {
                        $this->Flash->success(__('STIX document imported, event\'s created: ' . implode(', ', $result) . '.'));
                        $this->redirect(array('action' => 'index'));
                    } elseif (is_numeric($result)) {
                        $this->Flash->success(__('STIX document imported.'));
                        $this->redirect(array('action' => 'view', $result));
                    } else {
                        $this->Flash->error(__('Could not import STIX document: ' . $result));
                    }
                } else {
                    $max_size = intval(ini_get('post_max_size'));
                    if (intval(ini_get('upload_max_filesize')) < $max_size) {
                        $max_size = intval(ini_get('upload_max_filesize'));
                    }
                    $this->Flash->error(__('File upload failed. Make sure that you select a stix file to be uploaded and that the file doesn\'t exceed the maximum file size of ' . $max_size . '.'));
                }
            }
        }

        if ($stix_version == 2) {
            $stix_version = '2.x JSON';
        } else {
            $stix_version = '1.x XML';
        }
        $this->set('stix_version', $stix_version);
    }

    public function merge($target_id = null)
    {
        $this->Event->id = $target_id;
        $eIds = $this->Event->fetchEventIds($this->Auth->user(), false, false, false, true);
        // check if event exists and is readable for the current user
        if (!$this->Event->exists() || !in_array($target_id, $eIds)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $this->Event->read(null, $target_id);
        // check if private and user not authorised to edit
        if (!$this->_isSiteAdmin() && ($this->Event->data['Event']['orgc_id'] != $this->_checkOrg() || !($this->userRole['perm_modify']))) {
            $this->Flash->error(__("You are not authorised to do that. Please consider using the 'propose attribute' feature."));
            $this->redirect(array('action' => 'view', $target_id));
        }
        $this->Event->insertLock($this->Auth->user(), $target_id);
        if ($this->request->is('post')) {
            $source_id = trim($this->request->data['Event']['source_id']);
            $to_ids = $this->request->data['Event']['to_ids'];
            if (!is_numeric($source_id)) {
                $this->Flash->error(__('Invalid event ID entered.'));
                return;
            }
            $this->Event->read(null, $source_id);
            if (!$this->_isSiteAdmin() && !in_array($source_id, $eIds)) {
                $this->Flash->error(__('You are not authorised to read the selected event.'));
                return;
            }
            $r = array('results' => []);
            foreach ($this->Event->data['Attribute'] as $a) {
                if ($to_ids && !$a['to_ids']) {
                    continue;
                }
                $tmp = array();
                $tmp['values']     = $a['value'];
                $tmp['categories'] = $a['category'];
                $tmp['types']      = $a['type'];
                $tmp['to_ids']     = $a['to_ids'];
                $tmp['comment']    = $a['comment'];
                if ($this->Event->Attribute->typeIsAttachment($a['type'])) {
                    $encodedFile = $this->Event->Attribute->base64EncodeAttachment($a);
                    $tmp['data'] = $encodedFile;
                    $tmp['data_is_handled'] = true;
                }
                $r['results'][] = $tmp;
            }
            $resultArray = $this->Event->handleModuleResult($r, $target_id);
            $typeCategoryMapping = array();
            foreach ($this->Event->Attribute->categoryDefinitions as $k => $cat) {
                foreach ($cat['types'] as $type) {
                    $typeCategoryMapping[$type][$k] = $k;
                }
            }
            foreach ($resultArray as $key => $result) {
                $options = array(
                        'conditions' => array('OR' => array('Attribute.value1' => $result['value'], 'Attribute.value2' => $result['value'])),
                        'fields' => array('Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.comment'),
                        'order' => false
                );
                $resultArray[$key]['related'] = $this->Event->Attribute->fetchAttributes($this->Auth->user(), $options);
            }
            $this->set('event', array('Event' => array('id' => $target_id)));
            $this->set('resultArray', $resultArray);
            $this->set('typeList', array_keys($this->Event->Attribute->typeDefinitions));
            $this->set('defaultCategories', $this->Event->Attribute->defaultCategories);
            $this->set('typeCategoryMapping', $typeCategoryMapping);
            $this->set('title', 'Merge Results');
            $this->set('importComment', 'Merged from event ' . $source_id);
            $this->render('resolved_attributes');
        } else {
            // set the target event id in the form
            $this->request->data['Event']['target_id'] = $target_id;
        }
    }

    public function edit($id = null)
    {
        if ($this->request->is('get') && $this->_isRest()) {
            return $this->RestResponse->describe('Events', 'edit', false, $this->response->type());
        }
        if (Validation::uuid($id)) {
            $temp = $this->Event->find('first', array('recursive' => -1, 'fields' => array('Event.id'), 'conditions' => array('Event.uuid' => $id)));
            if (empty($temp)) {
                throw new NotFoundException(__('Invalid event'));
            }
            $id = $temp['Event']['id'];
        } elseif (!is_numeric($id)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $this->Event->id = $id;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid event'));
        }
        $this->Event->read(null, $id);
        // check if private and user not authorised to edit
        if (!$this->_isSiteAdmin() && !($this->userRole['perm_sync'] && $this->_isRest())) {
            if (($this->Event->data['Event']['orgc_id'] != $this->_checkOrg()) || !($this->userRole['perm_modify'])) {
                $message = __('You are not authorised to do that. Please consider using the \'propose attribute\' feature.');
                if ($this->_isRest()) {
                    throw new MethodNotAllowedException($message);
                } else {
                    $this->Flash->error($message);
                    $this->redirect(array('controller' => 'events', 'action' => 'index'));
                }
            }
        }
        if (!$this->_isRest()) {
            $this->Event->insertLock($this->Auth->user(), $id);
        }
        if ($this->request->is('post') || $this->request->is('put')) {
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
                $result = $this->Event->_edit($this->request->data, $this->Auth->user(), $id);
                if ($result === true) {
                    // REST users want to see the newly created event
                    $results = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id));
                    $event = $results[0];
                    $this->set('event', $event);
                    $this->render('view');
                    return true;
                } else {
                    $message = 'Error';
                    if ($this->_isRest()) {
                        App::uses('JSONConverterTool', 'Tools');
                        $converter = new JSONConverterTool();
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

            $this->Event->read();
            // always force the org, but do not force it for admins
            if (!$this->_isSiteAdmin()) {
                // set the same org as existed before
                $this->request->data['Event']['org_id'] = $this->Event->data['Event']['org_id'];
            }
            // we probably also want to remove the published flag
            $this->request->data['Event']['published'] = 0;
            $date = new DateTime();
            $this->request->data['Event']['timestamp'] = $date->getTimestamp();
            if ($this->Event->save($this->request->data, true, $fieldList)) {
                $this->Flash->success(__('The event has been saved'));
                $this->redirect(array('action' => 'view', $id));
            } else {
                $this->Flash->error(__('The event could not be saved. Please, try again.'));
            }
        } else {
            if (!$this->userRole['perm_modify']) {
                $this->redirect(array('controller' => 'events', 'action' => 'index', 'admin' => false));
            }
            $this->request->data = $this->Event->read(null, $id);
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
        $this->set('event', $this->Event->data);
        $this->render('add');
    }

    public function delete($id = null)
    {
        if (Validation::uuid($id)) {
            $temp = $this->Event->find('first', array('recursive' => -1, 'fields' => array('Event.id'), 'conditions' => array('Event.uuid' => $id)));
            if (empty($temp)) {
                throw new NotFoundException(__('Invalid event'));
            }
            $id = $temp['Event']['id'];
        }
        if ($this->request->is('post') || $this->request->is('put') || $this->request->is('delete')) {
            if (isset($this->request->data['id'])) {
                $this->request->data['Event'] = $this->request->data;
            }
            if (!isset($id) && isset($this->request->data['Event']['id'])) {
                $idList = $this->request->data['Event']['id'];
                if (!is_array($idList)) {
                    if (is_numeric($idList)) {
                        $idList = array($idList);
                    } else {
                        $idList = json_decode($idList, true);
                    }
                }
                if (!is_array($idList) || empty($idList)) {
                    throw new NotFoundException(__('Invalid input.'));
                }
            } else {
                $idList = array($id);
            }
            $fails = array();
            $successes = array();
            foreach ($idList as $eid) {
                if (!is_numeric($eid)) {
                    continue;
                }
                $event = $this->Event->find('first', array(
                    'conditions' => array('Event.id' => $eid),
                    'fields' => array('Event.orgc_id', 'Event.id'),
                    'recursive' => -1
                ));
                if (empty($event)) {
                    $fails[] = $eid;
                } else {
                    if (!$this->_isSiteAdmin()) {
                        if ($event['Event']['orgc_id'] != $this->_checkOrg() || !$this->userRole['perm_modify']) {
                            $fails[] = $eid;
                            continue;
                        }
                    }
                    $this->Event->insertLock($this->Auth->user(), $event['Event']['id']);
                    if ($this->Event->quickDelete($event)) {
                        $successes[] = $eid;
                    } else {
                        $fails[] = $eid;
                    }
                }
            }
            $message = '';
            if (count($idList) == 1) {
                if (!empty($successes)) {
                    $message = 'Event deleted.';
                } else {
                    $message = 'Event was not deleted.';
                }
            } else {
                if (!empty($successes)) {
                    $message .= count($successes) . ' event(s) deleted.';
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
            if (is_numeric($id)) {
                $eventList = array($id);
            } else {
                $eventList = json_decode($id, true);
            }
            $this->request->data['Event']['id'] = json_encode($eventList);
            $this->set('idArray', $eventList);
            $this->render('ajax/eventDeleteConfirmationForm');
        }
    }

    public function unpublish($id = null)
    {
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        $this->Event->id = $id;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid event'));
        }
        $this->Event->recursive = -1;
        $event = $this->Event->read(null, $id);
        if (!$this->_isSiteAdmin()) {
            if (!$this->userRole['perm_modify'] || $this->Auth->user('org_id') !== $this->Event->data['Event']['orgc_id']) {
                throw new MethodNotAllowedException(__('You don\'t have the permission to do that.'));
            }
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
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        $event = $this->Event->fetchEvent(
            $this->Auth->user(),
            array(
                'eventid' => $id,
                'metadata' => 1
            )
        );
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            $result = $this->Event->publishRouter($id, null, $this->Auth->user(), 'sightings');
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
                $this->set('url', '/events/publishSightings/' . $id);
                $this->set('id', $id);
                $this->set('_serialize', array('name', 'message', 'url', 'id', 'errors'));
            } else {
                $this->Flash->success($message);
                $this->redirect(array('action' => 'view', $id));
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
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        $this->Event->id = $id;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid event'));
        }
        // update the event and set the from field to the current instance's organisation from the bootstrap. We also need to save id and info for the logs.
        $this->Event->recursive = -1;
        $event = $this->Event->read(null, $id);
        if (!$this->_isSiteAdmin()) {
            if (!$this->userRole['perm_publish'] || $this->Auth->user('org_id') !== $this->Event->data['Event']['orgc_id']) {
                throw new MethodNotAllowedException(__('You don\'t have the permission to do that.'));
            }
        }
        $this->Event->insertLock($this->Auth->user(), $id);
        $success = true;
        $message = '';
        $errors = array();
        // only allow form submit CSRF protection.
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!$this->_isRest()) {
                $publishable = $this->Event->checkIfPublishable($id);
                if ($publishable !== true) {
                    $this->Flash->error(__('Could not publish event - no tag for required taxonomies missing: %s', implode(', ', $publishable)));
                    $this->redirect(array('action' => 'view', $id));
                }
            }
            // Performs all the actions required to publish an event
            $result = $this->Event->publishRouter($id, null, $this->Auth->user());
            if (!Configure::read('MISP.background_jobs')) {
                if (!is_array($result)) {
                    // redirect to the view event page
                    $message = 'Event published without alerts';
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $message = sprintf('Event published but not pushed to %s, re-try later. If the issue persists, make sure that the correct sync user credentials are used for the server link and that the sync user on the remote server has authentication privileges.', $resultString);
                }
            } else {
                // update the DB to set the published flag
                // for background jobs, this should be done already
                $fieldList = array('published', 'id', 'info', 'publish_timestamp');
                $event['Event']['published'] = 1;
                $event['Event']['publish_timestamp'] = time();
                $this->Event->save($event, array('fieldList' => $fieldList));
                $message = 'Job queued';
            }
            if ($this->_isRest()) {
                $this->set('name', 'Publish');
                $this->set('message', $message);
                if (!empty($errors)) {
                    $this->set('errors', $errors);
                }
                $this->set('url', '/events/alert/' . $id);
                $this->set('id', $id);
                $this->set('_serialize', array('name', 'message', 'url', 'id', 'errors'));
            } else {
                $this->Flash->success($message);
                $this->redirect(array('action' => 'view', $id));
            }
        } else {
            $this->set('id', $id);
            $this->set('type', 'publish');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    // Send out an alert email to all the users that wanted to be notified.
    // Users with a GnuPG key will get the mail encrypted, other users will get the mail unencrypted
    public function alert($id = null)
    {
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        $this->Event->id = $id;
        $this->Event->recursive = 0;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid event'));
        }
        $this->Event->recursive = -1;
        $this->Event->read(null, $id);
        if (!$this->_isSiteAdmin()) {
            if (!$this->userRole['perm_publish'] || $this->Auth->user('org_id') !== $this->Event->data['Event']['orgc_id']) {
                throw new MethodNotAllowedException(__('You don\'t have the permission to do that.'));
            }
        }
        $success = true;
        $message = '';
        $errors = array();
        // only allow form submit CSRF protection
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!$this->_isRest()) {
                $publishable = $this->Event->checkIfPublishable($id);
                if ($publishable !== true) {
                    $this->Flash->error(__('Could not publish event - no tag for required taxonomies missing: %s', implode(', ', $publishable)));
                    $this->redirect(array('action' => 'view', $id));
                }
            }
            // send out the email
            $emailResult = $this->Event->sendAlertEmailRouter($id, $this->Auth->user(), $this->Event->data['Event']['publish_timestamp']);
            if (is_bool($emailResult) && $emailResult == true) {
                // Performs all the actions required to publish an event
                $result = $this->Event->publishRouter($id, null, $this->Auth->user());
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
                    $failed = 1;
                    $message = sprintf('Not published given no connection to %s but email sent to all participants.', $resultString);
                }
            } elseif (!is_bool($emailResult)) {
                // Performs all the actions required to publish an event
                $result = $this->Event->publishRouter($id, null, $this->Auth->user());
                if (!is_array($result)) {
                    // redirect to the view event page
                    $message = 'Published but no email sent given GnuPG is not configured.';
                    $errors['GnuPG'] = 'GnuPG not set up.';
                } else {
                    $lastResult = array_pop($result);
                    $resultString = (count($result) > 0) ? implode(', ', $result) . ' and ' . $lastResult : $lastResult;
                    $errors['failed_servers'] = $result;
                    $errors['GnuPG'] = 'GnuPG not set up.';
                    $failed = 1;
                    $message = sprintf('Not published given no connection to %s but no email sent given GnuPG is not configured.', $resultString);
                }
            } else {
                $message = 'Sending of email failed';
                $errors['email'] = 'The sending of emails failed.';
            }
            if ($this->_isRest()) {
                $this->set('name', 'Alert');
                $this->set('message', $message);
                if (!empty($errors)) {
                    $this->set('errors', $errors);
                }
                $this->set('url', '/events/alert/' . $id);
                $this->set('id', $id);
                $this->set('_serialize', array('name', 'message', 'url', 'id', 'errors'));
            } else {
                if (!empty($failed)) {
                    $this->Flash->error($message);
                } else {
                    $this->Flash->success($message);
                }
                $this->redirect(array('action' => 'view', $id));
            }
        } else {
            $this->set('id', $id);
            $this->set('type', 'alert');
            $this->render('ajax/eventPublishConfirmationForm');
        }
    }

    // Send out an contact email to the person who posted the event.
    // Users with a GnuPG key will get the mail encrypted, other users will get the mail unencrypted
    public function contact($id = null)
    {
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        $this->Event->id = $id;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid event'));
        }
        // User has filled in his contact form, send out the email.
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!isset($this->request->data['Event'])) {
                $this->request->data = array('Event' => $this->request->data);
            }
            $message = $this->request->data['Event']['message'];
            if (empty($message)) {
                $error = __("You must specify a message.");
                if ($this->_isRest()) {
                    throw new MethodNotAllowedException($error);
                } else {
                    $this->Flash->error($error);
                    $this->redirect(array('action' => 'contact', $id));
                }
            }

            $creator_only = false;
            if (isset($this->request->data['Event']['person'])) {
                $creator_only = $this->request->data['Event']['person'];
            }
            $user = $this->Auth->user();
            $user['gpgkey'] = $this->Event->User->getPGP($user['id']);
            $user['certif_public'] = $this->Event->User->getCertificate($user['id']);

            $success = $this->Event->sendContactEmailRouter($id, $message, $creator_only, $user, $this->_isSiteAdmin());
            if ($success) {
                $return_message = __('Email sent to the reporter.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Events', 'contact', $id, $this->response->type(), $return_message);
                } else {
                    $this->Flash->success($return_message);
                    // redirect to the view event page
                    $this->redirect(array('action' => 'view', $id));
                }
            } else {
                $return_message = __('Sending of email failed.');
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('Events', 'contact', $id, $return_message, $this->response->type());
                } else {
                    $this->Flash->error($return_message, 'default', array(), 'error');
                    // redirect to the view event page
                    $this->redirect(array('action' => 'view', $id));
                }
            }
        }
        // User didn't see the contact form yet. Present it to him.
        if (empty($this->data)) {
            $this->data = $this->Event->read(null, $id);
        }
    }

    public function automation($legacy = false)
    {
        // Simply display a static view
        if (!$this->userRole['perm_auth']) {
            $this->redirect(array('controller' => 'events', 'action' => 'index'));
        }
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
        $this->loadModel('Attribute');
        $this->set('sigTypes', array_keys($this->Attribute->typeDefinitions));
        $this->loadModel('Server');
        $rpzSettings = $this->Server->retrieveCurrentSettings('Plugin', 'RPZ_');
        $this->set('rpzSettings', $rpzSettings);
        $this->set('hashTypes', array_keys($this->Event->Attribute->hashTypes));
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
        if (Configure::read('MISP.background_jobs') && !Configure::read('MISP.disable_cached_exports')) {
            $now = time();

            // as a site admin we'll use the ADMIN identifier, not to overwrite the cached files of our own org with a file that includes too much data.
            $org_name = $this->_isSiteAdmin() ? 'ADMIN' : $this->Auth->user('Organisation')['name'];
            $conditions = $this->Event->buildEventConditions($this->Auth->user());
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
            foreach ($this->Event->export_types as $k => $type) {
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
                        $this->Event->export_types[$k]['recommendation'] = 0;
                    } else {
                        $lastModified = 'N/A';
                        $this->Event->export_types[$k]['recommendation'] = 1;
                    }
                } else {
                    $filesize = $file->size();
                    $filesize_unit_index = 0;
                    while ($filesize > 1024) {
                        $filesize_unit_index++;
                        $filesize = $filesize / 1024;
                    }
                    $this->Event->export_types[$k]['filesize'] = round($filesize, 1) . $filesize_units[$filesize_unit_index];
                    $fileChange = $file->lastChange();
                    $lastModified = $this->__timeDifference($now, $fileChange);
                    if (empty($tempNewestEvent) || $fileChange > $tempNewestEvent['Event']['timestamp']) {
                        if (empty($tempNewestEvent)) {
                            $lastModified = 'No valid events';
                        }
                        $this->Event->export_types[$k]['recommendation'] = 0;
                    } else {
                        $this->Event->export_types[$k]['recommendation'] = 1;
                    }
                }

                $this->Event->export_types[$k]['lastModified'] = $lastModified;
                if (!empty($job)) {
                    $this->Event->export_types[$k]['job_id'] = $job['Job']['id'];
                    $this->Event->export_types[$k]['progress'] = $job['Job']['progress'];
                } else {
                    $this->Event->export_types[$k]['job_id'] = -1;
                    $this->Event->export_types[$k]['progress'] = 0;
                }
            }
        }
        $this->loadModel('Attribute');
        $this->set('sigTypes', array_keys($this->Attribute->typeDefinitions));
        $this->set('export_types', $this->Event->export_types);
    }

    public function downloadExport($type, $extra = null)
    {
        if (Configure::read('MISP.disable_cached_exports')) {
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
        $this->response->type($this->Event->export_types[$type]['extension']);
        $path = 'tmp/cached_exports/' . $type . DS . 'misp.' . strtolower($this->Event->export_types[$type]['type']) . $extra . '.' . $org . $this->Event->export_types[$type]['extension'];
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

    // Grab an event or a list of events for the event view or any of the XML exports. The returned object includes an array of events (or an array that only includes a single event if an ID was given)
    // Included with the event are the attached attributes, shadow attributes, related events, related attribute information for the event view and the creating user's email address where appropriate
    private function __fetchEvent($eventid = false, $idList = false, $user = false, $tags = false, $from = false, $to = false)
    {
        // if we come from automation, we may not be logged in - instead we used an auth key in the URL.
        if (empty($user)) {
            $user = $this->Auth->user();
        }
        $results = $this->Event->fetchEvent($user, array('eventid' => $eventid, 'idList' => $idList, 'tags' => $tags, 'from' => $from, 'to' => $to));
        return $results;
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
                'returnFormat' => 'csv'
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

            App::uses('FileAccessTool', 'Tools');
            $fileAccessTool = new FileAccessTool();
            $iocData = $fileAccessTool->readFromFile($this->data['Event']['submittedioc']['tmp_name'], $this->data['Event']['submittedioc']['size']);

        // write
        $attachments_dir = Configure::read('MISP.attachments_dir');
            if (empty($attachments_dir)) {
            $attachments_dir = $this->Event->getDefaultAttachments_dir();
        }
        $rootDir = $attachments_dir . DS . $id . DS;
            App::uses('Folder', 'Utility');
            $dir = new Folder($rootDir . 'ioc', true);
            $destPath = $rootDir . 'ioc';
            App::uses('File', 'Utility');
            $iocFile = new File($destPath . DS . $this->data['Event']['submittedioc']['name']);
            $result = $iocFile->write($iocData);
            if (!$result) {
                $this->Flash->error(__('Problem with writing the ioc file. Please report to administrator.'));
            }

            // open the xml
            $xmlFilePath = $destPath . DS . $this->data['Event']['submittedioc']['name'];
            $xmlFileData = $fileAccessTool->readFromFile($xmlFilePath, $this->data['Event']['submittedioc']['size']);

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
                    'Attribute' => array('event_id', 'category', 'type', 'value', 'value1', 'value2', 'to_ids', 'uuid', 'distribution', 'timestamp', 'comment')
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

    public function _addMISPExportFile($ext, $take_ownership = false, $publish = false)
    {
        App::uses('FileAccessTool', 'Tools');
        $data = (new FileAccessTool())->readFromFile($this->data['Event']['submittedfile']['tmp_name'], $this->data['Event']['submittedfile']['size']);

        if ($ext == 'xml') {
            App::uses('Xml', 'Utility');
            $dataArray = Xml::toArray(Xml::build($data));
        } else {
            $dataArray = json_decode($data, true);
            if (isset($dataArray['response'][0])) {
                foreach ($dataArray['response'] as $k => $temp) {
                    $dataArray['Event'][] = $temp['Event'];
                    unset($dataArray['response'][$k]);
                }
            }
        }
        // In case we receive an event that is not encapsulated in a response. This should never happen (unless it's a copy+paste fail),
        // but just in case, let's clean it up anyway.
        if (isset($dataArray['Event'])) {
            $dataArray['response']['Event'] = $dataArray['Event'];
            unset($dataArray['Event']);
        }
        if (!isset($dataArray['response']) || !isset($dataArray['response']['Event'])) {
            throw new Exception(__('This is not a valid MISP XML file.'));
        }
        $dataArray = $this->Event->updateXMLArray($dataArray);
        $results = array();
        $validationIssues = array();
        if (isset($dataArray['response']['Event'][0])) {
            foreach ($dataArray['response']['Event'] as $k => $event) {
                $result = array('info' => $event['info']);
                if ($take_ownership) {
                    $event['orgc_id'] = $this->Auth->user('org_id');
                    unset($event['Orgc']);
                }
                $event = array('Event' => $event);
                $created_id = 0;
                $event['Event']['locked'] = 1;
                $event['Event']['published'] = $publish;
                $result['result'] = $this->Event->_add($event, true, $this->Auth->user(), '', null, false, null, $created_id, $validationIssues);
                $result['id'] = $created_id;
                $result['validationIssues'] = $validationIssues;
                $results[] = $result;
            }
        } else {
            $temp['Event'] = $dataArray['response']['Event'];
            if ($take_ownership) {
                $temp['Event']['orgc_id'] = $this->Auth->user('org_id');
                unset($temp['Event']['Orgc']);
            }
            $created_id = 0;
            $temp['Event']['locked'] = 1;
            $temp['Event']['published'] = $publish;
            $result = $this->Event->_add($temp, true, $this->Auth->user(), '', null, false, null, $created_id, $validationIssues);
            $results = array(0 => array('info' => $temp['Event']['info'], 'result' => $result, 'id' => $created_id, 'validationIssues' => $validationIssues));
        }
        return $results;
    }

    private function __strposarray($string, $array)
    {
        $toReturn = false;
        foreach ($array as $item) {
            if (strpos($string, $item)) {
                $toReturn = true;
            }
        }
        return $toReturn;
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
            $user = $this->checkAuthUser($key);
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
        $this->loadModel('Whitelist');
        $temp = $this->Whitelist->removeWhitelistedFromArray(array($event[0]), false);
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
        $this->ShadowAttribute->recursive = -1;
        $conditions = array('ShadowAttribute.deleted' => 0);
        if (!$this->_isSiteAdmin()) {
            $conditions[] = array('ShadowAttribute.event_org_id' => $this->Auth->user('org_id'));
        }
        $result = $this->ShadowAttribute->find('all', array(
                'fields' => array('event_id'),
                'group' => array('event_id', 'id'),
                'conditions' => $conditions
        ));
        $this->Event->recursive = -1;
        $conditions = array();
        foreach ($result as $eventId) {
            $conditions['OR'][] = array('Event.id =' => $eventId['ShadowAttribute']['event_id']);
        }
        if (empty($result)) {
            $conditions['OR'][] = array('Event.id =' => -1);
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
        ));
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
        $this->loadModel('Taxonomy');
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
        $this->Event->recursive = -1;
        $event = $this->Event->read(array(), $id);
        if (empty($event)) {
            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid event.')), 'status'=>200, 'type' => 'json'));
        }
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
            if (!$this->_isSiteAdmin() && !$this->userRole['perm_sync']) {
                if (
                    !$this->userRole['perm_tagger'] ||
                    (
                        $this->Auth->user('org_id') !== $event['Event']['orgc_id']
                    )
                ) {
                    if (Configure::read('MISP.host_org_id') != $this->Auth->user('org_id') || !$local) {
                        return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
                    }
                }
            }
            $conditions = array('LOWER(Tag.name) LIKE' => strtolower(trim($tag_id)));
            if (!$this->_isSiteAdmin()) {
                $conditions['Tag.org_id'] = array('0', $this->Auth->user('org_id'));
                $conditions['Tag.user_id'] = array('0', $this->Auth->user('id'));
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
                        $tag = $this->Event->EventTag->Tag->find('first', array('recursive' => -1, 'conditions' => $conditions));
                        if (empty($tag)) {
                            return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid Tag.')), 'status'=>200, 'type' => 'json'));
                        }
                        $tag_id = $tag['Tag']['id'];
                    }
                }
            }
            $this->autoRender = false;
            $error = false;
            $success = false;
            if (empty($tag_id_list)) {
                $tag_id_list = array($tag_id);
            }
            foreach ($tag_id_list as $tag_id) {
                $this->Event->EventTag->Tag->id = $tag_id;
                if (!$this->Event->EventTag->Tag->exists()) {
                    $error = __('Invalid Tag.');
                    continue;
                }
                $tag = $this->Event->EventTag->Tag->find('first', array(
                    'conditions' => array('Tag.id' => $tag_id),
                    'recursive' => -1,
                    'fields' => array('Tag.name')
                ));
                $found = $this->Event->EventTag->find('first', array(
                    'conditions' => array(
                        'event_id' => $id,
                        'tag_id' => $tag_id
                    ),
                    'recursive' => -1,
                ));
                if (!empty($found)) {
                    $error = __('Tag is already attached to this event.');
                    continue;
                }
                $tagsOnEvent = $this->Event->EventTag->find('all', array(
                    'conditions' => array(
                        'EventTag.event_id' => $id,
                        'EventTag.local' => $local
                    ),
                    'contain' => 'Tag',
                    'fields' => array('Tag.name'),
                    'recursive' => -1
                ));
                $exclusiveTestPassed = $this->Taxonomy->checkIfNewTagIsAllowedByTaxonomy($tag['Tag']['name'], Hash::extract($tagsOnEvent, '{n}.Tag.name'));
                if (!$exclusiveTestPassed) {
                    $fail = __('Tag is not allowed due to taxonomy exclusivity settings');
                    continue;
                }
                $this->Event->EventTag->create();
                if ($this->Event->EventTag->save(array('event_id' => $id, 'tag_id' => $tag_id, 'local' => $local))) {
                    if (!$local) {
                        $event['Event']['published'] = 0;
                        $date = new DateTime();
                        $event['Event']['timestamp'] = $date->getTimestamp();
                        $this->Event->save($event);
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
                    $success = __('Tag(s) added.');
                } else {
                    $fail = __('Tag could not be added.');
                }
            }
            if ($success) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => __('Tag(s) added.'), 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
            } elseif (empty($fail)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => __('All tags are already present, nothing to add.'), 'check_publish' => true)), 'status'=>200, 'type' => 'json'));
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => $fail)), 'status'=>200, 'type' => 'json'));
            }
        }
    }

    public function removeTag($id = false, $tag_id = false, $galaxy = false)
    {
        if (!$this->request->is('post')) {
            $this->set('id', $id);
            $this->set('tag_id', $tag_id);
            $this->set('model', 'Event');
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

            // org should allow to (un)tag too, so that an event that gets pushed can be (un)tagged locally by the owning org
            if (
                (
                    (
                        $this->Auth->user('org_id') !== $event['Event']['orgc_id'] ||
                        (
                            $this->Auth->user('org_id') != Configure::read('MISP.host_org_id') &&
                            !empty($eventTag['EventTag']['local'])
                        )
                    ) ||
                    !$this->userRole['perm_tagger']
                ) &&
                !$this->_isSiteAdmin()
            ) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'You don\'t have permission to do that.')), 'status'=>200, 'type' => 'json'));
            }
            $this->Event->insertLock($this->Auth->user(), $id);
            $this->autoRender = false;
            if (empty($eventTag)) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Invalid event - ' . ($galaxy ? 'galaxy' : 'tag') . ' combination.')), 'status'=>200, 'type' => 'json'));
            }
            $tag = $this->Event->EventTag->Tag->find('first', array(
                'conditions' => array('Tag.id' => $tag_id),
                'recursive' => -1,
                'fields' => array('Tag.name')
            ));
            if ($this->Event->EventTag->delete($eventTag['EventTag']['id'])) {
                if (empty($eventTag['EventTag']['local'])) {
                    $event['Event']['published'] = 0;
                    $date = new DateTime();
                    $event['Event']['timestamp'] = $date->getTimestamp();
                    $this->Event->save($event);
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
        if (!$this->userRole['perm_add']) {
            throw new MethodNotAllowedException(__('Event not found or you don\'t have permissions to create attributes'));
        }
        $event = $this->Event->find('first', array(
                'conditions' => array('Event.id' => $id),
                'fields' => array('id', 'orgc_id'),
                'recursive' => -1
        ));
        $this->set('event_id', $id);
        if ($this->request->is('get')) {
            $this->layout = 'ajax';
            $this->request->data['Attribute']['event_id'] = $id;
        }

        if ($this->request->is('post')) {
            App::uses('ComplexTypeTool', 'Tools');
            $complexTypeTool = new ComplexTypeTool();
            $this->loadModel('Warninglist');
            $complexTypeTool->setTLDs($this->Warninglist->fetchTLDLists());
            if (!isset($this->request->data['Attribute'])) {
                $this->request->data = array('Attribute' => $this->request->data);
            }
            if (!isset($this->request->data['Attribute']['value'])) {
                $this->request->data['Attribute'] = array('value' => $this->request->data['Attribute']);
            }
            if (isset($this->request->data['Attribute']['adhereToWarninglists'])) {
                $adhereToWarninglists = $this->request->data['Attribute']['adhereToWarninglists'];
            }
            $resultArray = $complexTypeTool->checkComplexRouter($this->request->data['Attribute']['value'], 'freetext');
            foreach ($resultArray as $key => $r) {
                $temp = array();
                foreach ($r['types'] as $type) {
                    $temp[$type] = $type;
                }
                $resultArray[$key]['types'] = $temp;
            }

            // remove all duplicates
            foreach ($resultArray as $k => $v) {
                for ($i = 0; $i < $k; $i++) {
                    if (isset($resultArray[$i]) && $v == $resultArray[$i]) {
                        unset($resultArray[$k]);
                    }
                }
            }
            if ($this->_isRest()) {
                if ($returnMetaAttributes || !empty($this->request->data['Attribute']['returnMetaAttributes'])) {
                    return $this->RestResponse->viewData($resultArray, $this->response->type());
                } else {
                    return $this->__pushFreetext(
                        $resultArray,
                        $id,
                        isset($this->request->data['Attribute']['distribution']) ? $this->request->data['Attribute']['distribution'] : false,
                        isset($this->request->data['Attribute']['sharing_group_id']) ? $this->request->data['Attribute']['sharing_group_id'] : false,
                        $adhereToWarninglists
                    );
                }
            }
            foreach ($resultArray as $key => $result) {
                $options = array(
                    'conditions' => array('OR' => array('Attribute.value1' => $result['value'], 'Attribute.value2' => $result['value'])),
                    'fields' => array('Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.comment'),
                    'order' => false,
                    'flatten' => 1
                );
                $resultArray[$key]['related'] = $this->Event->Attribute->fetchAttributes($this->Auth->user(), $options);
            }
            $resultArray = array_values($resultArray);
            $typeCategoryMapping = array();
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

            $this->set('proposals', $event['Event']['orgc_id'] != $this->Auth->user('org_id') && !$this->_isSiteAdmin());
            $this->set('distributions', $distributions);
            $this->set('sgs', $sgs);
            $this->set('event', $event);
            $this->set('typeList', array_keys($this->Event->Attribute->typeDefinitions));
            $this->set('defaultCategories', $this->Event->Attribute->defaultCategories);
            $this->set('typeCategoryMapping', $typeCategoryMapping);
            foreach ($typeCategoryMapping as $k => $v) {
                $typeCategoryMapping[$k] = array_values($v);
            }
            $this->set('mapping', $typeCategoryMapping);
            $this->set('resultArray', $resultArray);
            $this->set('importComment', '');
            $this->set('title', 'Freetext Import Results');
            $this->loadModel('Warninglist');
            $tldLists = $this->Warninglist->getTldLists();
            $missingTldLists = array();
            foreach ($tldLists as $tldList) {
                $temp = $this->Warninglist->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('Warninglist.name' => $tldList),
                    'fields' => array('Warninglist.id')
                ));
                if (empty($temp)) {
                    $missingTldLists[] = $tldList;
                }
            }
            $this->set('missingTldLists', $missingTldLists);
            $this->render('resolved_attributes');
        }
    }

    public function __pushFreetext($attributes, $id, $distribution = false, $sg = false, $adhereToWarninglists = false)
    {
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        if ($distribution === false) {
            if (Configure::read('MISP.default_attribute_distribution') != null) {
                if (Configure::read('MISP.default_attribute_distribution') == 'event') {
                    $distribution = 5;
                } else {
                    $distribution = Configure::read('MISP.default_attribute_distribution');
                }
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
                $attribute['category'] = $this->Event->Attribute->defaultCategories[$attribute['type']];
            }
            $attribute['distribution'] = $distribution;
            $attribute['event_id'] = $id;
            $attributes[$k] = $attribute;
        }
        // actually save the attribute now
        $temp = $this->Event->processFreeTextDataRouter($this->Auth->user(), $attributes, $id, '', false, $adhereToWarninglists, empty(Configure::read('MISP.background_jobs')));
        if (empty(Configure::read('MISP.background_jobs'))) {
            $attributes = $temp;
        }
        // FIXME $attributes does not contain the onteflyattributes
        $attributes = array_values($attributes);
        return $this->RestResponse->viewData($attributes, $this->response->type());
    }

    public function saveFreeText($id)
    {
        if (!$this->userRole['perm_add']) {
            throw new MethodNotAllowedException(__('Event not found or you don\'t have permissions to create attributes'));
        }
        if ($this->request->is('post')) {
            if (!$this->Event->checkIfAuthorised($this->Auth->user(), $id)) {
                throw new MethodNotAllowedException(__('Invalid event.'));
            }
            $this->Event->insertLock($this->Auth->user(), $id);
            $attributes = json_decode($this->request->data['Attribute']['JsonObject'], true);
            $default_comment = $this->request->data['Attribute']['default_comment'];
            $force = $this->request->data['Attribute']['force'];
            $flashMessage = $this->Event->processFreeTextDataRouter($this->Auth->user(), $attributes, $id, $default_comment, $force);
            $this->Flash->info($flashMessage);
            $this->redirect(array('controller' => 'events', 'action' => 'view', $id));
        } else {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
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
        if (!$this->userRole['perm_sync']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if ($this->request->is('post')) {
            $incomingIDs = array();
            $incomingEvents = array();
            foreach ($this->request->data as $event) {
                $incomingIDs[] = $event['Event']['uuid'];
                $incomingEvents[$event['Event']['uuid']] = $event['Event']['timestamp'];
            }
            $events = $this->Event->find('all', array(
                'conditions' => array('Event.uuid' => $incomingIDs),
                'recursive' => -1,
                'fields' => array('Event.uuid', 'Event.timestamp', 'Event.locked'),
            ));
            foreach ($events as $k => $v) {
                if ($v['Event']['timestamp'] >= $incomingEvents[$v['Event']['uuid']]) {
                    unset($incomingEvents[$v['Event']['uuid']]);
                    continue;
                }
                if ($v['Event']['locked'] == 0) {
                    unset($incomingEvents[$v['Event']['uuid']]);
                }
            }
            $this->set('result', array_keys($incomingEvents));
        }
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
                            $temp = json_encode($oldsa);
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
                        $this->Event->ShadowAttribute->__sendProposalAlertEmail($event['Event']['id']);
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
        if (!is_numeric($id)) {
            throw new MethodNotAllowedException(__('Invalid ID'));
        }
        $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id));
        if (empty($event)) {
            throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
        }
        $event = $event[0];
        // #TODO i18n
        $exports = array(
            'xml' => array(
                    'url' => '/events/restSearch/xml/eventid:' . $id . '.xml',
                    'text' => 'MISP XML (metadata + all attributes)',
                    'requiresPublished' => false,
                    'checkbox' => true,
                    'checkbox_text' => 'Encode Attachments',
                    'checkbox_set' => '/events/restSearch/xml/eventid:' . $id . '/withAttachments:1.xml',
                    'checkbox_default' => true
            ),
            'json' => array(
                    'url' => '/events/restSearch/json/eventid:' . $id . '.json',
                    'text' => 'MISP JSON (metadata + all attributes)',
                    'requiresPublished' => false,
                    'checkbox' => true,
                    'checkbox_text' => 'Encode Attachments',
                    'checkbox_set' => '/events/restSearch/json/withAttachments:1/eventid:' . $id . '.json',
                    'checkbox_default' => true
            ),
            'openIOC' => array(
                    'url' => '/events/downloadOpenIOCEvent/download/' . $id,
                    'text' => 'OpenIOC (all indicators marked to IDS)',
                    'requiresPublished' => false,
                    'checkbox' => false,
            ),
            'csv' => array(
                    'url' => '/events/csv/download/' . $id,
                    'text' => 'CSV',
                    'requiresPublished' => false,
                    'checkbox' => true,
                    'checkbox_text' => 'Include non-IDS marked attributes',
                    'checkbox_set' => '/events/csv/download/' . $id . '/1'
            ),
            'csv_with_context' => array(
                    'url' => '/events/restSearch/returnFormat:csv/eventid:' . $id,
                    'text' => 'CSV with additional context',
                    'requiresPublished' => false,
                    'checkbox' => true,
                    'checkbox_text' => 'Include non-IDS marked attributes',
                    'checkbox_set' => '/events/restSearch/returnFormat:csv/to_ids:1||0/published:1||0/eventid:' . $id
            ),
            'stix_xml' => array(
                    'url' => '/events/restSearch/stix/eventid:' . $id,
                    'text' => 'STIX XML (metadata + all attributes)',
                    'requiresPublished' => false,
                    'checkbox' => true,
                    'checkbox_text' => 'Encode Attachments',
                    'checkbox_set' => '/events/restSearch/stix/eventid:' . $id . '/withAttachments:1'
            ),
            'stix_json' => array(
                    'url' => '/events/restSearch/stix-json/eventid:' . $id,
                    'text' => 'STIX JSON (metadata + all attributes)',
                    'requiresPublished' => false,
                    'checkbox' => true,
                    'checkbox_text' => 'Encode Attachments',
                    'checkbox_set' => '/events/restSearch/stix-json/withAttachments:1/eventid:' . $id
            ),
            'stix2_json' => array(
                    'url' => '/events/restSearch/stix2/eventid:' . $id,
                    'text' => 'STIX2 (requires the STIX 2 library)',
                    'requiresPublished' => false,
                    'checkbox' => true,
                    'checkbox_text' => 'Encode Attachments',
                    'checkbox_set' => '/events/restSearch/stix2/eventid:' . $id . '/withAttachments:1'
            ),
            'rpz' => array(
                    'url' => '/attributes/restSearch/returnFormat:rpz/published:1||0/eventid:' . $id,
                    'text' => 'RPZ Zone file',
                    'requiresPublished' => false,
                    'checkbox' => false,
            ),
            'suricata' => array(
                    'url' => '/events/restSearch/returnFormat:suricata/published:1||0/eventid:' . $id,
                    'text' => 'Download Suricata rules',
                    'requiresPublished' => false,
                    'checkbox' => false,
            ),
            'snort' => array(
                    'url' => '/events/restSearch/returnFormat:snort/published:1||0/eventid:' . $id,
                    'text' => 'Download Snort rules',
                    'requiresPublished' => false,
                    'checkbox' => false,
            ),
            'bro' => array(
                    'url' => '/attributes/bro/download/all/false/' . $id,
                    'text' => 'Download Bro rules',
                    'requiresPublished' => false,
                    'checkbox' => false
            ),
            'text' => array(
                    'text' => 'Export all attribute values as a text file',
                    'url' => '/attributes/restSearch/returnFormat:text/published:1||0/eventid:' . $id,
                    'requiresPublished' => false,
                    'checkbox' => true,
                    'checkbox_text' => 'Include non-IDS marked attributes',
                    'checkbox_set' => '/attributes/restSearch/returnFormat:text/published:1||0/to_ids:1||0/eventid:' . $id
            ),
        );
        if ($event['Event']['published'] == 0) {
            foreach ($exports as $k => $export) {
                if ($export['requiresPublished']) {
                    unset($exports[$k]);
                }
            }
            $exports['csv'] = array(
                'url' => '/events/csv/download/' . $id . '/1',
                'text' => 'CSV (event not published, IDS flag ignored)',
                'requiresPublished' => false,
                'checkbox' => false
            );
        }
        $this->loadModel('Module');
        $modules = $this->Module->getEnabledModules($this->Auth->user(), false, 'Export');
        if (is_array($modules) && !empty($modules)) {
            foreach ($modules['modules'] as $module) {
                $exports[$module['name']] = array(
                        'url' => '/events/exportModule/' . $module['name'] . '/' . $id,
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
        if ($scope == 'event') {
            if (!is_numeric($id)) {
                throw new MethodNotAllowedException(__('Invalid ID'));
            }
            $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id));
            if (empty($event)) {
                throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
            }
            $event = $event[0];
            // #TODO i18n
            $imports = array(
                    'freetext' => array(
                            'url' => '/events/freeTextImport/' . $id,
                            'text' => 'Freetext Import',
                            'ajax' => true,
                            'target' => 'popover_form'
                    ),
                    'template' => array(
                            'url' => '/templates/templateChoices/' . $id,
                            'text' => 'Populate using a Template',
                            'ajax' => true,
                            'target' => 'popover_form'
                    ),
                    'OpenIOC' => array(
                            'url' => '/events/addIOC/' . $id,
                            'text' => 'OpenIOC Import',
                            'ajax' => false,
                    ),
                    'ThreatConnect' => array(
                            'url' => '/attributes/add_threatconnect/' . $id,
                            'text' => 'ThreatConnect Import',
                            'ajax' => false
                    ),
                    'Forensic analysis' => array(
                        'url' => '/events/upload_analysis_file/'.$id,
                        'text' => '(Experimental) Forensic analysis - Mactime',
                        'ajax' => false,
                )
            );
            $this->loadModel('Module');
            $modules = $this->Module->getEnabledModules($this->Auth->user(), false, 'Import');
            if (is_array($modules) && !empty($modules)) {
                foreach ($modules['modules'] as $k => $module) {
                    $imports[$module['name']] = array(
                            'url' => '/events/importModule/' . $module['name'] . '/' . $id,
                            'text' => Inflector::humanize($module['name']),
                            'ajax' => false
                    );
                }
            }
        } else {
            $imports = array(
                'MISP' => array(
                        'url' => '/events/add_misp_export',
                        'text' => 'MISP standard (recommended exchange format - lossless)',
                        'ajax' => false,
                        'bold' => true
                ),
                'STIX' => array(
                        'url' => '/events/upload_stix',
                        'text' => 'STIX 1.1.1 format (lossy)',
                        'ajax' => false,
                ),
                'STIX2' => array(
                        'url' => '/events/upload_stix/2',
                        'text' => 'STIX 2.0 format (lossy)',
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
                $this->Log->save(array(
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
        $fileAccessTool = new FileAccessTool();
        foreach ($data['files'] as $file) {
            $tmpdir = Configure::read('MISP.tmpdir') ? Configure::read('MISP.tmpdir') : APP . 'tmp';
            $tmpfile = $fileAccessTool->createTempFile($tmpdir, $prefix = 'MISP_upload');
            $fileAccessTool->writeToFile($tmpfile, base64_decode($file['data']));
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
            $fileAccessTool->deleteFile($tmpfile->path);
        }
        if (!empty($errors)) {
            $this->set('errors', $errors);
            if ($successCount > 0) {
                $this->set('name', 'Partial success');
                $this->set('message', 'Successfuly saved ' . $successCount . ' sample(s), but some samples could not be saved.');
                $this->set('url', '/events/view/' . $data['settings']['event_id']);
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
            $this->set('url', '/events/view/' . $data['settings']['event_id']);
            $this->set('id', $data['settings']['event_id']);
            $this->set('_serialize', array('name', 'message', 'url', 'id'));
        }
        $this->view($data['settings']['event_id']);
        $this->render('view');
    }

    public function viewGraph($id)
    {
        $event = $this->Event->fetchEvent($this->Auth->user(), array(
            'eventid' => $id,
            'includeGranularCorrelations' => 1
        ));
        if (empty($event)) {
            throw new MethodNotAllowedException(__('Invalid Event.'));
        }

        $this->set('event', $event[0]);
        $this->set('scope', 'event');
        $this->set('id', $id);
    }

    public function viewEventGraph()
    {
        $event = $this->Event->fetchEvent($this->Auth->user(), array(
            'eventid' => $id
        ));
        if (empty($event)) {
            throw new MethodNotAllowedException(__('Invalid Event.'));
        }
        $this->set('event', $event[0]);
        $this->set('scope', 'event');
        $this->set('id', $id);
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
        $validTools = array('event', 'galaxy', 'tag');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $this->loadModel('Taxonomy');
        $this->loadModel('GalaxyCluster');
        App::uses('CorrelationGraphTool', 'Tools');
        $grapher = new CorrelationGraphTool();
        $data = $this->request->is('post') ? $this->request->data : array();
        $grapher->construct($this->Event, $this->Taxonomy, $this->GalaxyCluster, $this->Auth->user(), $data);
        $json = $grapher->buildGraphJson($id, $type);
        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        $this->response->type('json');
        return new CakeResponse(array('body' => json_encode($json), 'status' => 200, 'type' => 'json'));
    }

    private function genDistributionGraph($id, $type = 'event', $extended = 0) {
        $validTools = array('event');
        if (!in_array($type, $validTools)) {
            throw new MethodNotAllowedException(__('Invalid type.'));
        }
        $this->loadModel('Server');
        $this->loadModel('Organisation');
        App::uses('DistributionGraphTool', 'Tools');
        $grapher = new DistributionGraphTool();

        $servers = $this->Server->find('list', array(
            'fields' => array('name'),
        ));
        $grapher->construct($this->Event, $servers, $this->Auth->user(), $extended);
        $json = $grapher->get_distributions_graph($id);

        array_walk_recursive($json, function (&$item, $key) {
            if (!mb_detect_encoding($item, 'utf-8', true)) {
                $item = utf8_encode($item);
            }
        });
        return $json;
    }

    public function getDistributionGraph($id, $type = 'event')
    {
        $extended = isset($this->params['named']['extended']) ? 1 : 0;
        $json = $this->genDistributionGraph($id, $type, $extended);
        $this->response->type('json');
        return new CakeResponse(array('body' => json_encode($json), 'status' => 200, 'type' => 'json'));
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
        $this->response->type('json');
        return new CakeResponse(array('body' => json_encode($json), 'status' => 200, 'type' => 'json'));
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
        $this->response->type('json');
        return new CakeResponse(array('body' => json_encode($json), 'status' => 200, 'type' => 'json'));
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
        $this->response->type('json');
        return new CakeResponse(array('body' => json_encode($json), 'status' => 200, 'type' => 'json'));
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
        $this->response->type('json');
        return new CakeResponse(array('body' => json_encode($json), 'status' => 200, 'type' => 'json'));
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
        $this->response->type('json');
        return new CakeResponse(array('body' => json_encode($json), 'status' => 200, 'type' => 'json'));
    }

    public function viewGalaxyMatrix($scope_id, $galaxy_id, $scope='event', $disable_picking=false)
    {
        $local = !empty($this->params['named']['local']);
        $this->set('local', $local);
        $this->loadModel('Galaxy');
        $mitreAttackGalaxyId = $this->Galaxy->getMitreAttackGalaxyId();
        $matrixData = $this->Galaxy->getMatrix($galaxy_id);

        $tabs = $matrixData['tabs'];
        $matrixTags = $matrixData['matrixTags'];
        $killChainOrders = $matrixData['killChain'];
        $instanceUUID = $matrixData['instance-uuid'];

        if ($scope == 'event') {
            $eventId = $scope_id;
        } elseif ($scope == 'attribute') {
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
        } elseif ($scope == 'tag_collection') {
            $eventId = 0; // no event_id for tag_collection, consider all events
        } else {
            throw new Exception("Invalid options.");
        }

        if ($scope !== 'tag_collection') {
            $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $eventId, 'metadata' => true));
            if (empty($event)) {
                throw new NotFoundException(__('Event not found or you are not authorised to view it.'));
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
            $this->response->type('json');
            return new CakeResponse(array('body' => json_encode($json), 'status' => 200, 'type' => 'json'));
        } else {
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
        $threat_levels = $this->Event->ThreatLevel->find('all');
        $this->set('threatLevels', Set::combine($threat_levels, '{n}.ThreatLevel.id', '{n}.ThreatLevel.name'));
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

    // expects an attribute ID and the module to be used
    public function queryEnrichment($attribute_id, $module = false, $type = 'Enrichment')
    {
        if (!Configure::read('Plugin.' . $type . '_services_enable')) {
            throw new MethodNotAllowedException(__('%s services are not enabled.', $type));
        }
        $attribute = $this->Event->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $attribute_id), 'flatten' => 1));
        if (empty($attribute)) {
            throw new MethodNotAllowedException(__('Attribute not found or you are not authorised to see it.'));
        }
        $this->loadModel('Module');
        $enabledModules = $this->Module->getEnabledModules($this->Auth->user(), false, $type);
        if (!is_array($enabledModules) || empty($enabledModules)) {
            throw new MethodNotAllowedException(__('No valid %s options found for this attribute.', $type));
        }
        if ($this->request->is('ajax')) {
            $modules = array();
            foreach ($enabledModules['modules'] as $module) {
                if (in_array($attribute[0]['Attribute']['type'], $module['mispattributes']['input'])) {
                    $modules[] = array('name' => $module['name'], 'description' => $module['meta']['description']);
                }
            }
            foreach (array('attribute_id', 'modules') as $viewVar) {
                $this->set($viewVar, $$viewVar);
            }
            $this->set('type', $type);
            $this->render('ajax/enrichmentChoice');
        } else {
            $options = array();
            foreach ($enabledModules['modules'] as $temp) {
                if ($temp['name'] == $module) {
                    $format = (!empty($temp['mispattributes']['format']) ? $temp['mispattributes']['format'] : 'simplified');
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
            if ($format == 'misp_standard') {
                $this->__queryEnrichment($attribute, $module, $options, $type);
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
        $data = json_encode($data);
        $result = $this->Module->queryModuleServer('/query', $data, false, $type);
        if (!$result) {
            throw new MethodNotAllowedException(__('%s service not reachable.', $type));
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
            $this->set('title', 'Enrichment Results');
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
        $data = json_encode($data);
        $result = $this->Module->queryModuleServer('/query', $data, false, $type);
        if (!$result) {
            throw new MethodNotAllowedException(__('%s service not reachable.', $type));
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
        foreach ($resultArray as $key => $result) {
            $options = array(
                    'conditions' => array('OR' => array('Attribute.value1' => $result['value'], 'Attribute.value2' => $result['value'])),
                    'fields' => array('Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.comment'),
                    'order' => false
            );
            $resultArray[$key]['related'] = $this->Event->Attribute->fetchAttributes($this->Auth->user(), $options);
            if (isset($result['data'])) {
                App::uses('FileAccessTool', 'Tools');
                $fileAccessTool = new FileAccessTool();
                $tmpdir = Configure::read('MISP.tmpdir') ? Configure::read('MISP.tmpdir') : '/tmp';
                $tempFile = $fileAccessTool->createTempFile($tmpdir, $prefix = 'MISP');
                $fileAccessTool->writeToFile($tempFile, $result['data']);
                $resultArray[$key]['data'] = basename($tempFile) . '|' . filesize($tempFile);
            }
        }
        $this->set('type', $type);
        if (!$event){
            $this->set('event', array('Event' => $attribute[0]['Event']));
        }
        $this->set('resultArray', $resultArray);
        $this->set('typeList', array_keys($this->Event->Attribute->typeDefinitions));
        $this->set('defaultCategories', $this->Event->Attribute->defaultCategories);
        $this->set('typeCategoryMapping', $typeCategoryMapping);
        $this->set('title', 'Enrichment Results');
        $this->set('importComment', $importComment);
        $this->render('resolved_attributes');
    }

    public function handleModuleResults($id)
    {
        if (!$this->userRole['perm_add']) {
            throw new MethodNotAllowedException(__('Event not found or you don\'t have permissions to create attributes'));
        }
        if ($this->request->is('post')) {
            if (!$this->Event->checkIfAuthorised($this->Auth->user(), $id)) {
                throw new MethodNotAllowedException(__('Invalid event.'));
            }
            $resolved_data = json_decode($this->request->data['Event']['JsonObject'], true);
            $data = json_decode($this->request->data['Event']['data'], true);
            if (!empty($data['initialObject'])) {
                $resolved_data['initialObject'] = $data['initialObject'];
            }
            unset($data);
            $default_comment = $this->request->data['Event']['default_comment'];
            $flashMessage = $this->Event->processModuleResultsDataRouter($this->Auth->user(), $resolved_data, $id, $default_comment);
            $this->Flash->info($flashMessage);
            $this->redirect(array('controller' => 'events', 'action' => 'view', $id));
        } else {
            throw new MethodNotAllowedException('This endpoint requires a POST request.');
        }
    }

    public function importModule($module, $eventId)
    {
        $this->loadModel('Module');
        $moduleName = $module;
        if (!$this->Event->checkIfAuthorised($this->Auth->user(), $eventId)) {
            throw new MethodNotAllowedException(__('Invalid event.'));
        }
        $module = $this->Module->getEnabledModule($module, 'Import');
        if (!is_array($module)) {
            throw new MethodNotAllowedException($module);
        }
        if (!isset($module['mispattributes']['inputSource'])) {
            $module['mispattributes']['inputSource'] = array('paste');
        }
        if ($this->request->is('post')) {
            $fail = false;
            $modulePayload = array(
                    'module' => $module['name'],
                    'event_id' => $eventId
            );
            if (isset($module['meta']['config'])) {
                foreach ($module['meta']['config'] as $conf) {
                    $modulePayload['config'][$conf] = Configure::read('Plugin.Import_' . $moduleName . '_' . $conf);
                }
            }
            if ($moduleName === 'csvimport') {
                if (empty($this->request->data['Event']['config']['header']) && $this->request->data['Event']['config']['has_header'] === '1') {
                    $this->request->data['Event']['config']['header'] = ' ';
                }
                if (empty($this->request->data['Event']['config']['special_delimiter'])) {
                    $this->request->data['Event']['config']['special_delimiter'] = ' ';
                }
            }
            foreach ($module['mispattributes']['userConfig'] as $configName => $config) {
                if (!$fail) {
                    if (isset($config['validation'])) {
                        if ($config['validation'] === '0' && $config['type'] == 'String') {
                            $validation = true;
                        }
                    } else {
                        $validation = call_user_func_array(array($this->Module, $this->Module->configTypes[$config['type']]['validation']), array($this->request->data['Event']['config'][$configName]));
                    }
                    if ($validation !== true) {
                        $fail = ucfirst($configName) . ': ' . $validation;
                    } else {
                        if (isset($config['regex']) && !empty($config['regex'])) {
                            $fail = preg_match($config['regex'], $this->request->data['Event']['config'][$configName]) ? false : ucfirst($configName) . ': ' . 'Invalid setting' . ($config['errorMessage'] ? ' - ' . $config['errorMessage'] : '');
                            if (!empty($fail)) {
                                $modulePayload['config'][$configName] = $this->request->data['Event']['config'][$configName];
                            }
                        } else {
                            $modulePayload['config'][$configName] = $this->request->data['Event']['config'][$configName];
                        }
                    }
                }
            }
            if (!$fail) {
                if (!empty($module['mispattributes']['inputSource'])) {
                    if (!isset($this->request->data['Event']['source'])) {
                        if (in_array('paste', $module['mispattributes']['inputSource'])) {
                            $this->request->data['Event']['source'] = '0';
                        } else {
                            $this->request->data['Event']['source'] = '1';
                        }
                    }
                    if ($this->request->data['Event']['source'] == '1') {
                        if (isset($this->request->data['Event']['data'])) {
                            $modulePayload['data'] = base64_decode($this->request->data['Event']['data']);
                        } elseif (!isset($this->request->data['Event']['fileupload']) || empty($this->request->data['Event']['fileupload'])) {
                            $fail = 'Invalid file upload.';
                        } else {
                            $fileupload = $this->request->data['Event']['fileupload'];
                            $tmpfile = new File($fileupload['tmp_name']);
                            if ((isset($fileupload['error']) && $fileupload['error'] == 0) || (!empty($fileupload['tmp_name']) && $fileupload['tmp_name'] != 'none') && is_uploaded_file($tmpfile->path)) {
                                $filename = basename($fileupload['name']);
                                App::uses('FileAccessTool', 'Tools');
                                $modulePayload['data'] = (new FileAccessTool())->readFromFile($fileupload['tmp_name'], $fileupload['size']);
                            } else {
                                $fail = 'Invalid file upload.';
                            }
                        }
                    } else {
                        $modulePayload['data'] = $this->request->data['Event']['paste'];
                    }
                } else {
                    $modulePayload['data'] = '';
                }
                if (!$fail) {
                    $modulePayload['data'] = base64_encode($modulePayload['data']);
                    if (!empty($filename)) {
                        $modulePayload['filename'] = $filename;
                    }
                    $result = $this->Module->queryModuleServer('/query', json_encode($modulePayload, true), false, $moduleFamily = 'Import');
                    if (!$result) {
                        throw new Exception(__('Import service not reachable.'));
                    }
                    if (isset($result['error'])) {
                        $this->Flash->error($result['error']);
                    }
                    if (!is_array($result)) {
                        throw new Exception($result);
                    }
                    $importComment = !empty($result['comment']) ? $result['comment'] : 'Enriched via the ' . $module['name'] . ' module';
                    if (!empty($module['mispattributes']['format']) && $module['mispattributes']['format'] === 'misp_standard') {
                        $event = $this->Event->handleMispFormatFromModuleResult($result);
                        $event['Event'] = array('id' => $eventId);
                        if ($this->_isRest()) {
                            $this->Event->processModuleResultsDataRouter($this->Auth->user(), $event, $eventId, $importComment);
                            return $this->RestResponse->viewData($event, $this->response->type());
                        }
                        $this->set('event', $event);
                        $this->set('menuItem', 'importResults');
                        $render_name = 'resolved_misp_format';
                    } else {
                        $resultArray = $this->Event->handleModuleResult($result, $eventId);
                        if ($this->_isRest()) {
                            return $this->__pushFreetext(
                                $resultArray,
                                $eventId,
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
                        foreach ($resultArray as $key => $result) {
                            $options = array(
                                    'conditions' => array('OR' => array('Attribute.value1' => $result['value'], 'Attribute.value2' => $result['value'])),
                                    'fields' => array('Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.comment'),
                                    'order' => false
                            );
                            $resultArray[$key]['related'] = $this->Event->Attribute->fetchAttributes($this->Auth->user(), $options);
                        }
                        $this->set('event', array('Event' => array('id' => $eventId)));
                        $this->set('resultArray', $resultArray);
                        $this->set('typeList', array_keys($this->Event->Attribute->typeDefinitions));
                        $this->set('defaultCategories', $this->Event->Attribute->defaultCategories);
                        $this->set('typeCategoryMapping', $typeCategoryMapping);
                        $render_name = 'resolved_attributes';
                    }
                    $distributions = $this->Event->Attribute->distributionLevels;
                    $sgs = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
                    if (empty($sgs)) {
                        unset($distributions[4]);
                    }
                    $this->set('distributions', $distributions);
                    $this->set('sgs', $sgs);
                    $this->set('title', 'Import Results');
                    $this->set('importComment', $importComment);
                    $this->render($render_name);
                }
            } else {
                $this->Flash->error($fail);
            }
        }
        $this->set('configTypes', $this->Module->configTypes);
        $this->set('module', $module);
        $this->set('eventId', $eventId);
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
        if (!$this->_isSiteAdmin() && Configure.read('MISP.allow_disabling_correlation')) {
            throw new MethodNotAllowedException(__('Disabling the correlation is not permitted on this instance.'));
        }
        $this->Event->id = $id;
        if (!$this->Event->exists()) {
            throw new NotFoundException(__('Invalid Event.'));
        }
        if (!$this->Auth->user('Role')['perm_modify']) {
            throw new MethodNotAllowedException(__('You don\'t have permission to do that.'));
        }
        $conditions = array('Event.id' => $id);
        if (!$this->_isSiteAdmin()) {
            $conditions['Event.orgc_id'] = $this->Auth->user('org_id');
        }
        $event = $this->Event->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1
        ));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid Event.'));
        }
        if (!$this->Auth->user('Role')['perm_modify_org'] && $this->Auth->user('id') != $event['Event']['user_id']) {
            throw new MethodNotAllowedException(__('You don\'t have permission to do that.'));
        }
        if ($this->request->is('post')) {
            if ($event['Event']['disable_correlation']) {
                $event['Event']['disable_correlation'] = 0;
                $this->Event->save($event);
                $attributes = $this->Event->Attribute->find('all', array(
                    'conditions' => array('Attribute.event_id' => $id),
                    'recursive' => -1
                ));
                foreach ($attributes as $attribute) {
                    $this->Event->Attribute->__afterSaveCorrelation($attribute['Attribute'], false, $event);
                }
            } else {
                $event['Event']['disable_correlation'] = 1;
                $this->Event->save($event);
                $this->Event->Attribute->purgeCorrelations($id);
            }
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('events', 'toggleCorrelation', $id, false, 'Correlation ' . ($event['Event']['disable_correlation'] ? 'disabled' : 'enabled') . '.');
            } else {
                $this->Flash->success('Correlation ' . ($event['Event']['disable_correlation'] ? 'disabled' : 'enabled') . '.');
                $this->redirect(array('controller' => 'events', 'action' => 'view', $id));
            }
        } else {
            $this->set('event', $event);
            $this->render('ajax/toggle_correlation');
        }
    }

    public function checkPublishedStatus($id)
    {
        $event = $this->Event->fetchEvent($this->Auth->user(), array('metadata' => 1, 'eventid' => $id));
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        return new CakeResponse(array('body'=> h($event[0]['Event']['published']), 'status'=>200, 'type' => 'txt'));
    }
    // #TODO i18n
    public function pushEventToZMQ($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Event, $id);
        if ($this->request->is('Post')) {
            if (Configure::read('Plugin.ZeroMQ_enable')) {
                $pubSubTool = $this->Event->getPubSubTool();
                $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $id));
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
                    $params = array('eventid' => $id);
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
        if (empty($id)) {
            throw new MethodNotAllowedException(__('Invalid ID.'));
        }
        $conditions = array('Event.id' => $id);
        if (Validation::uuid($id)) {
            $conditions = array('Event.uuid' => $id);
        } elseif (!is_numeric($id)) {
            $conditions = array('Event.uuid' => -1);
        }
        $event = $this->Event->find('first', array(
            'conditions' => $conditions,
            'fields' => array('Event.id', 'Event.distribution', 'Event.sharing_group_id', 'Event.info', 'Event.org_id', 'Event.date', 'Event.threat_level_id', 'Event.analysis'),
            'contain' => array('Orgc.id', 'Orgc.name', 'EventTag' => array('Tag.id', 'Tag.name', 'Tag.colour'), 'ThreatLevel.name'),
            'recursive' => -1
        ));
        if (!empty($event) && !$this->_isSiteAdmin() && $event['Event']['org_id'] != $this->Auth->user('org_id')) {
            if (!in_array($event['Event']['distribution'], array(1, 2, 3))) {
                if ($event['Event']['distribution'] == 4) {
                    $sharingGroups = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user());
                    if (!in_array($event['Event']['sharing_group_id'], $sharingGroups)) {
                        $event = array();
                    }
                } else {
                    $event = array();
                }
            }
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($event, $this->response->type());
        } else {
            if ($this->request->is('ajax')) {
                $this->layout = 'ajax';
            }
            $this->set('analysisLevels', $this->Event->analysisLevels);
            $this->set('validUuid', Validation::uuid($id));
            $this->set('id', $id);
            $this->set('event', $event);
        }
    }

    public function enrichEvent($id)
    {
        if (Validation::uuid($id)) {
            $conditions = array('Event.uuid' => $id);
        } else {
            $conditions = array('Event.id' => $id);
        }
        $event = $this->Event->find('first', array('conditions' => $conditions, 'recursive' => -1));
        if (empty($event) || (!$this->_isSiteAdmin() && ($this->Auth->user('org_id') != $event['Event']['orgc_id'] || !$this->userRole['perm_modify']))) {
            throw new MethodNotAllowedException(__('Invalid Event'));
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
            $this->layout = 'ajax';
            $this->set('modules', $modules);
            $this->render('ajax/enrich_event');
        }
    }

    public function checkLocks($id)
    {
        $this->loadModel('EventLock');
        $event = $this->Event->find('first', array(
            'recursive' => -1,
            'conditions' => array('Event.id' => $id),
            'fields' => array('Event.orgc_id')
        ));
        $locks = array();
        if (!empty($event) && ($event['Event']['orgc_id'] == $this->Auth->user('org_id') || $this->_isSiteAdmin())) {
            $locks = $this->EventLock->checkLock($this->Auth->user(), $id);
        }
        if (!empty($locks)) {
            $temp = $locks;
            $locks = array();
            foreach ($temp as $t) {
                if ($t['User']['id'] !== $this->Auth->user('id')) {
                    if (!$this->_isSiteAdmin() && $t['User']['org_id'] != $this->Auth->user('org_id')) {
                        continue;
                    }
                    $locks[] = $t['User']['email'];
                }
            }
        }
        // TODO: i18n
        if (!empty($locks)) {
            $message = sprintf('Warning: Your view on this event might not be up to date as it is currently being edited by: %s', implode(', ', $locks));
            $this->set('message', $message);
            $this->layout = false;
            $this->render('/Events/ajax/event_lock');
        } else {
            return $this->RestResponse->viewData('', $this->response->type(), false, true);
        }
    }

    public function getEditStrategy($id)
    {
        // find the id of the event, change $id to it and proceed to read the event as if the ID was entered.
        if (Validation::uuid($id)) {
            $this->Event->recursive = -1;
            $event = $this->Event->find('first', array(
                'recursive' => -1,
                'conditions' => array('Event.uuid' => $id),
                'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id')
            ));
            if ($event == null) {
                throw new NotFoundException(__('Invalid event'));
            }
            $id = $event['Event']['id'];
        } elseif (!is_numeric($id)) {
            throw new NotFoundException(__('Invalid event'));
        } else {
            $event = $this->Event->find('first', array(
                'recursive' => -1,
                'conditions' => array('Event.id' => $id),
                'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id')
            ));
        }
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event'));
        }
        $response = array('extensions' => array());
        if ($event['Event']['orgc_id'] === $this->Auth->user('org_id')) {
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
                    'template_uuid' => '9297982e-be62-4772-a665-c91f5a8d639'
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
                $ObjectResult = $this->MispObject->saveObject($object, $eventId, "", "");
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
                    $result = $this->MispObject->ObjectReference->captureReference($objectRef, $eventId, $this->Auth->user(), false);
                    $objectRef['referenced_id'] = $temp['Object']['id'];
                    $objectRef['referenced_uuid'] = $temp['Object']['uuid'];
                    $objectRef['object_id'] = $PreviousObjRef['Object']['id'];
                    $objectRef['relationship_type'] = "followed-by";
                    $this->loadModel('MispObject');
                    $result = $this->MispObject->ObjectReference->captureReference($objectRef, $eventId, $this->Auth->user(), false);
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
        $this->Event->skipBlacklist = true;
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
        $this->Event->skipBlacklist = null;
        $message = __('%s event(s) deleted.', $count);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($message, $this->response->type());
        } else {
            $this->Flash->success($message);
            $this->redirect($this->referer());
        }
    }
}
