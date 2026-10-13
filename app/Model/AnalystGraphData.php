<?php
App::uses('AppModel', 'Model');
App::uses('AnalystGraphDocumentTool', 'Tools');
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');

/**
 * An analyst graph as one user sees it: the nodes they may read, their
 * records shaped as the Pivot Explorer's builders read them, and the edges
 * MISP holds between them. A node the user cannot read is left out without
 * a trace.
 */
class AnalystGraphData extends AppModel
{
    public $useTable = false;

    /** Nodes drawn at once: Pivotick's detail threshold. */
    const NODE_BUDGET = 1500;

    /** Nodes a thumbnail draws. */
    const THUMBNAIL_BUDGET = 300;

    private $models = [];

    private function model($alias)
    {
        if (!isset($this->models[$alias])) {
            $this->models[$alias] = ClassRegistry::init($alias);
        }
        return $this->models[$alias];
    }

    /**
     * @param array $user
     * @param array $document A stored graph document, decoded
     * @param int $budget The visible nodes, in document order, that get records
     * @return array
     */
    public function resolve(array $user, array $document, $budget = self::NODE_BUDGET)
    {
        $visible = $this->visibleNodes($user, $document['nodes'] ?? []);
        $drawn = array_slice($visible, 0, $budget);
        $skipped = array_slice($visible, $budget);
        $uuids = $this->uuidsByType($drawn);

        $objects = $this->objects($user, $uuids['Object']);
        $attributes = $this->attributes($user, $uuids['Attribute']);
        $clusters = $this->clusters($user, $uuids['GalaxyCluster']);
        $values = [];
        foreach ($drawn as $node) {
            if ($node['type'] === 'Value') {
                $values[] = [
                    'uuid' => $node['uuid'],
                    'value' => $node['value'],
                    'b64' => ValueUrlTool::encode($node['value']),
                ];
            }
        }
        $events = $this->events($user, $uuids['Event'], $objects, $attributes);

        $document = AnalystGraphDocumentTool::withNodes($document, $visible);
        $document['view'] = (object)($document['view'] ?? []);
        $priorities = $this->model('ObjectTemplate')->uiPrioritiesFor($objects);
        return [
            'document' => $document,
            'Object' => $objects,
            'Attribute' => $attributes,
            'GalaxyCluster' => $clusters,
            'Value' => $values,
            'events' => $events ?: new stdClass(),
            'ui_priorities' => $priorities ?: new stdClass(),
            'edges' => $this->edges($user, $uuids['Event'], $objects, $attributes, $clusters, $values, $events, $this->answersOf($drawn)),
            'meta' => [
                'nodes' => count($visible),
                'drawn' => count($drawn),
                'skipped' => array_map(['AnalystGraphDocumentTool', 'nodeKey'], $skipped),
                'budget' => $budget,
            ],
        ];
    }

    /**
     * The edges MISP holds between these nodes, as resolve() derives them for
     * a stored graph: what a canvas of them would show once saved.
     *
     * @param array $user
     * @param array $nodes Graph document nodes
     * @return array [edges or null, errors]; Value nodes as {uuid, value}
     */
    public function edgesBetween(array $user, array $nodes)
    {
        list($document, $errors) = AnalystGraphDocumentTool::normalise([
            'version' => AnalystGraphDocumentTool::VERSION,
            'nodes' => $nodes,
        ]);
        if (!empty($errors)) {
            return [null, $errors];
        }
        $payload = $this->resolve($user, $document);
        $values = array_map(function ($value) {
            return ['uuid' => $value['uuid'], 'value' => $value['value']];
        }, $payload['Value']);
        return [['edges' => $payload['edges'], 'Value' => $values], []];
    }

    /**
     * What a thumbnail of the graph draws for this user: the first
     * THUMBNAIL_BUDGET nodes they may read, each at its saved position when it
     * has one, and the edges `data` derives between them. An attribute inside
     * a drawn object is the object, as the explorer draws it; hidden edges
     * stay hidden.
     *
     * @param array $user
     * @param array $document A stored graph document, decoded
     * @return array {nodes: [{key, type, x?, y?, pinned?}], edges: [[from, to, kind]], total}
     *               edges by index into nodes; total counts every node the user may read
     */
    public function thumbnail(array $user, array $document)
    {
        $payload = $this->resolve($user, $document, self::THUMBNAIL_BUDGET);
        $parent = [];
        foreach ($payload['Object'] as $object) {
            $objectKey = 'Object:' . strtolower($object['uuid']);
            foreach ($object['Attribute'] as $attribute) {
                $parent['Attribute:' . strtolower($attribute['uuid'])] = $objectKey;
            }
        }
        $nodes = [];
        $index = [];
        foreach (array_slice($payload['document']['nodes'], 0, self::THUMBNAIL_BUDGET) as $node) {
            $key = AnalystGraphDocumentTool::nodeKey($node);
            if (isset($parent[$key])) {
                continue;
            }
            $thumb = ['key' => $key, 'type' => $node['type']];
            if (isset($node['x'], $node['y']) && is_numeric($node['x']) && is_numeric($node['y'])) {
                $thumb['x'] = round((float)$node['x'], 1);
                $thumb['y'] = round((float)$node['y'], 1);
            }
            if (!empty($node['pinned'])) {
                $thumb['pinned'] = true;
            }
            $index[$key] = count($nodes);
            $nodes[] = $thumb;
        }
        $hidden = array_flip($document['hidden_edges'] ?? []);
        $edges = [];
        foreach ($payload['edges'] as $edge) {
            if ($edge['kind'] === 'contains' || isset($hidden[$edge['id']])) {
                continue;
            }
            $from = $index[$edge['from']] ?? $index[$parent[$edge['from']] ?? ''] ?? null;
            $to = $index[$edge['to']] ?? $index[$parent[$edge['to']] ?? ''] ?? null;
            if ($from === null || $to === null || $from === $to) {
                continue;
            }
            $pair = min($from, $to) . '-' . max($from, $to);
            if (!isset($edges[$pair])) {
                $edges[$pair] = [$from, $to, $edge['kind']];
            }
        }
        return [
            'nodes' => $nodes,
            'edges' => array_values($edges),
            'total' => $payload['meta']['nodes'],
        ];
    }

    /**
     * The nodes the user may read, in document order. A Value node is
     * authored content of the graph, so it is always readable. A module
     * answer comes with only the origins the user passes (answerFilter()).
     *
     * @param array $user
     * @param array $nodes Normalised nodes
     * @return array
     */
    public function visibleNodes(array $user, array $nodes)
    {
        return $this->visibleNodeLists($user, [$nodes])[0];
    }

    /**
     * visibleNodes() for several graphs, with one readability lookup per type
     * for all of them.
     *
     * @param array $user
     * @param array $lists key => normalised nodes
     * @return array key => the readable nodes, in document order
     */
    public function visibleNodeLists(array $user, array $lists)
    {
        return $this->filterNodeLists($user, $lists, false);
    }

    /**
     * A stored document as this user may receive it. Every path that hands a
     * document out goes through here: a module answer carries content, so a
     * path that skipped it would leak more than a uuid.
     *
     * @param array $user
     * @param array $document Decoded
     * @param bool $keepRecords Keep record nodes as stored, filtering answers only
     * @return array
     */
    public function documentFor(array $user, array $document, $keepRecords = false)
    {
        return $this->documentsFor($user, [$document], $keepRecords)[0];
    }

    /**
     * documentFor() for several documents, with one lookup per type for all.
     *
     * @param array $user
     * @param array $documents key => decoded document
     * @param bool $keepRecords
     * @return array key => document
     */
    public function documentsFor(array $user, array $documents, $keepRecords = false)
    {
        $lists = [];
        foreach ($documents as $key => $document) {
            $lists[$key] = is_array($document['nodes'] ?? null) ? $document['nodes'] : [];
        }
        $filtered = $this->filterNodeLists($user, $lists, $keepRecords);
        foreach ($documents as $key => $document) {
            if (is_array($document)) {
                $documents[$key] = AnalystGraphDocumentTool::withNodes($document, $filtered[$key]);
            }
        }
        return $documents;
    }

    /**
     * @param array $user
     * @param array $lists key => normalised nodes
     * @param bool $keepRecords
     * @return array key => nodes, in document order
     */
    private function filterNodeLists(array $user, array $lists, $keepRecords)
    {
        $byType = [];
        foreach ($lists as $nodes) {
            foreach ($nodes as $node) {
                if (AnalystGraphDocumentTool::isAnswer($node)) {
                    foreach ($node['origins'] as $origin) {
                        list($type, $uuid) = explode(':', $origin['node'], 2);
                        if ($type === 'Attribute') {
                            $byType['Attribute'][$uuid] = true;
                        }
                    }
                } elseif ($node['type'] !== 'Value' && !$keepRecords) {
                    $byType[$node['type']][$node['uuid']] = true;
                }
            }
        }
        $readable = [];
        $elements = $this->model('CollectionElement');
        foreach ($byType as $type => $uuids) {
            foreach ($elements->readableUuids($user, $type, array_map('strval', array_keys($uuids))) as $uuid) {
                $readable[$type][strtolower($uuid)] = true;
            }
        }
        $out = [];
        foreach ($lists as $key => $nodes) {
            $answers = $this->answerFilter($user, $nodes, $readable['Attribute'] ?? []);
            $out[$key] = [];
            foreach ($nodes as $node) {
                if (AnalystGraphDocumentTool::isAnswer($node)) {
                    if (isset($answers[$node['uuid']])) {
                        $out[$key][] = $answers[$node['uuid']];
                    }
                } elseif ($keepRecords || $node['type'] === 'Value' || isset($readable[$node['type']][$node['uuid']])) {
                    $out[$key][] = $node;
                }
            }
        }
        return $out;
    }

    /**
     * The module answers of one document the user may see. An answer is seen
     * when one of its origins passes and the user's organisation may use the
     * module whose content it holds. An origin passes when that organisation
     * may use the module asked and what was asked is visible: an attribute
     * they can read, any Value, or an answer they see. Each answer keeps only
     * the origins and modules the user passes.
     *
     * @param array $user
     * @param array $nodes Normalised nodes
     * @param array $readable Lowercase attribute uuid => true, for those the user may read
     * @return array uuid => the answer as the user receives it
     */
    private function answerFilter(array $user, array $nodes, array $readable)
    {
        return $this->keptAnswers($nodes, $user, function ($uuid) use ($readable) {
            return isset($readable[$uuid]);
        });
    }

    /**
     * The answers that pass for one organisation, as answerFilter() describes,
     * with what counts as a visible attribute origin left to the caller.
     *
     * @param array $nodes Normalised nodes
     * @param array $user Whose organisation the module test is for
     * @param callable $attributePasses Given a lowercase attribute uuid
     * @return array uuid => the answer, with the origins and modules that pass
     */
    private function keptAnswers(array $nodes, array $user, callable $attributePasses)
    {
        $answers = [];
        foreach ($nodes as $node) {
            if (AnalystGraphDocumentTool::isAnswer($node)) {
                $answers[$node['uuid']] = $node;
            }
        }
        if (empty($answers)) {
            return [];
        }
        $seen = [];
        $passes = function (array $origin) use ($user, $attributePasses, &$seen) {
            if (!$this->mayUseModule($user, $origin['module'])) {
                return false;
            }
            list($type, $uuid) = explode(':', $origin['node'], 2);
            if ($type === 'Value') {
                return true;
            }
            return $type === 'Attribute' ? $attributePasses($uuid) : isset($seen[$uuid]);
        };
        // Answers can be asked about answers, in chains and in loops
        do {
            $grew = false;
            foreach ($answers as $uuid => $answer) {
                if (isset($seen[$uuid]) || !$this->mayUseModule($user, $answer['module'])) {
                    continue;
                }
                foreach ($answer['origins'] as $origin) {
                    if ($passes($origin)) {
                        $seen[$uuid] = true;
                        $grew = true;
                        break;
                    }
                }
            }
        } while ($grew);
        $out = [];
        foreach (array_keys($seen) as $uuid) {
            $answer = $answers[$uuid];
            $answer['origins'] = array_values(array_filter($answer['origins'], $passes));
            $answer['modules'] = array_values(array_filter($answer['modules'], function ($module) use ($user) {
                return $this->mayUseModule($user, $module);
            }));
            $out[$uuid] = $answer;
        }
        return $out;
    }

    /**
     * A stored document as it is pushed to a server: the records as stored,
     * and the module answers that server's organisation would see here. An
     * answer goes when that organisation may use its module and one of its
     * origins goes too: an attribute whose distribution lets it be pushed to
     * that server, a Value, or another answer that goes. It carries only
     * those origins, since an origin holds the value that was asked.
     *
     * @param array $document Decoded
     * @param array $server A Server row
     * @return array
     */
    public function documentForServer(array $document, array $server)
    {
        $nodes = is_array($document['nodes'] ?? null) ? $document['nodes'] : [];
        $uuids = [];
        foreach ($nodes as $node) {
            if (is_array($node) && AnalystGraphDocumentTool::isAnswer($node)) {
                foreach ($node['origins'] as $origin) {
                    list($type, $uuid) = explode(':', $origin['node'], 2);
                    if ($type === 'Attribute') {
                        $uuids[$uuid] = true;
                    }
                }
            }
        }
        $reaching = empty($uuids) ? [] : $this->attributesReaching($server, array_map('strval', array_keys($uuids)));
        $remote = [
            'org_id' => $server['Server']['remote_org_id'] ?? null,
            'Role' => ['perm_site_admin' => 0],
        ];
        $kept = $this->keptAnswers($nodes, $remote, function ($uuid) use ($reaching) {
            return isset($reaching[$uuid]);
        });
        $out = [];
        foreach ($nodes as $node) {
            if (!is_array($node) || !AnalystGraphDocumentTool::isAnswer($node)) {
                $out[] = $node;
            } elseif (isset($kept[$node['uuid']])) {
                $out[] = $kept[$node['uuid']];
            }
        }
        return AnalystGraphDocumentTool::withNodes($document, $out);
    }

    /**
     * Of these attributes, the ones a push may carry to this server: their
     * event, their object and themselves each pass the distribution check an
     * event push applies. Whether the event is published yet is when it goes,
     * not whether.
     *
     * @param array $server
     * @param string[] $uuids Lowercase
     * @return array uuid => true
     */
    private function attributesReaching(array $server, array $uuids)
    {
        if (empty($server['RemoteOrg']['uuid']) && !empty($server['Server']['remote_org_id'])) {
            $org = $this->model('Organisation')->find('first', [
                'conditions' => ['Organisation.id' => $server['Server']['remote_org_id']],
                'fields' => ['Organisation.id', 'Organisation.uuid'],
                'recursive' => -1,
            ]);
            $server['RemoteOrg'] = $org['Organisation'] ?? [];
        }
        $attributes = $this->model('MispAttribute')->find('all', [
            'conditions' => ['Attribute.uuid' => $uuids],
            'fields' => ['Attribute.uuid', 'Attribute.event_id', 'Attribute.object_id', 'Attribute.distribution', 'Attribute.sharing_group_id'],
            'recursive' => -1,
        ]);
        if (empty($attributes)) {
            return [];
        }
        $attributes = array_column($attributes, 'Attribute');
        $byId = function (array $rows, $alias) {
            $out = [];
            foreach ($rows as $row) {
                $out[$row[$alias]['id']] = $row[$alias];
            }
            return $out;
        };
        $events = $byId($this->model('Event')->find('all', [
            'conditions' => ['Event.id' => array_values(array_unique(array_map('strval', array_column($attributes, 'event_id'))))],
            'fields' => ['Event.id', 'Event.distribution', 'Event.sharing_group_id'],
            'recursive' => -1,
        ]), 'Event');
        $objectIds = array_values(array_filter(array_unique(array_map('strval', array_column($attributes, 'object_id')))));
        $objects = empty($objectIds) ? [] : $byId($this->model('MispObject')->find('all', [
            'conditions' => ['Object.id' => $objectIds],
            'fields' => ['Object.id', 'Object.distribution', 'Object.sharing_group_id'],
            'recursive' => -1,
        ]), 'Object');

        $levels = [];
        foreach ($attributes as $a) {
            $chain = [$events[$a['event_id']] ?? null];
            if (!empty($a['object_id'])) {
                $chain[] = $objects[$a['object_id']] ?? null;
            }
            $chain[] = $a;
            $levels[strtolower($a['uuid'])] = $chain;
        }
        $sgIds = [];
        foreach ($levels as $chain) {
            foreach ($chain as $level) {
                if ($level !== null && (int)$level['distribution'] === 4) {
                    $sgIds[$level['sharing_group_id']] = true;
                }
            }
        }
        $sharingGroups = [];
        foreach (empty($sgIds) ? [] : $this->model('SharingGroup')->find('all', [
            'conditions' => ['SharingGroup.id' => array_map('strval', array_keys($sgIds))],
            'contain' => [
                'SharingGroupServer' => ['fields' => ['id', 'server_id', 'all_orgs']],
                'SharingGroupOrg' => ['Organisation' => ['fields' => ['id', 'uuid']]],
            ],
        ]) as $row) {
            $sharingGroups[$row['SharingGroup']['id']] = $row;
        }

        $Event = $this->model('Event');
        $reaching = [];
        foreach ($levels as $uuid => $chain) {
            $goes = true;
            foreach ($chain as $level) {
                if ($level === null) {
                    $goes = false;
                    break;
                }
                $distribution = (int)$level['distribution'];
                if ($distribution === 5) {
                    continue;
                }
                $check = ['Event' => ['distribution' => $distribution]];
                if ($distribution === 4) {
                    if (!isset($sharingGroups[$level['sharing_group_id']])) {
                        $goes = false;
                        break;
                    }
                    $check['SharingGroup'] = $sharingGroups[$level['sharing_group_id']];
                }
                if (!$Event->checkDistributionForPush($check, $server, 'Event')) {
                    $goes = false;
                    break;
                }
            }
            if ($goes) {
                $reaching[$uuid] = true;
            }
        }
        return $reaching;
    }

    private $moduleUse = [];

    /**
     * Whether the user's organisation may use a module: its `_restrict`
     * setting only. The role's right to run modules is about cost, and an
     * answer already kept costs nothing.
     *
     * @param array $user
     * @param string $module
     * @return bool
     */
    private function mayUseModule(array $user, $module)
    {
        $key = ($user['org_id'] ?? '') . ':' . (empty($user['Role']['perm_site_admin']) ? 0 : 1) . ':' . $module;
        if (!isset($this->moduleUse[$key])) {
            $this->moduleUse[$key] = $this->model('Module')->canUse($user, 'Enrichment', ['name' => $module]);
        }
        return $this->moduleUse[$key];
    }

    /**
     * The document a write stores, as far as module answers go (the record
     * nodes are the writer's). An answer already stored keeps its content,
     * module and origins, gaining any origin the write brings; a new origin
     * must be one the writer can name — an attribute they can read, a Value,
     * or an answer the document holds — and an answer left with none is not
     * kept. Stored answers the writer cannot see are put back: only the
     * answers they could see and left out are removed. Last, an answer whose
     * origins are all gone goes: every attribute origin deleted for good,
     * every answer origin out of the document. A Value origin never goes.
     *
     * @param array $user The writer
     * @param array $incoming Normalised
     * @param array|null $stored The stored document, decoded; null on create
     * @return array The document to store
     */
    public function documentForWrite(array $user, array $incoming, $stored = null)
    {
        $storedAnswers = [];
        foreach (($stored['nodes'] ?? []) as $node) {
            if (is_array($node) && AnalystGraphDocumentTool::isAnswer($node) && isset($node['uuid'], $node['origins'], $node['content'])) {
                $storedAnswers[$node['uuid']] = $node;
            }
        }
        $seenStored = empty($storedAnswers) ? [] : array_flip(array_column(
            array_filter($this->visibleNodes($user, array_values($storedAnswers)), ['AnalystGraphDocumentTool', 'isAnswer']),
            'uuid'
        ));

        $nodes = [];
        $incomingAnswers = [];
        foreach ($incoming['nodes'] ?? [] as $node) {
            if (!AnalystGraphDocumentTool::isAnswer($node)) {
                $nodes[] = $node;
                continue;
            }
            $uuid = $node['uuid'];
            $incomingAnswers[$uuid] = true;
            if (!isset($storedAnswers[$uuid])) {
                $node['_new'] = array_fill_keys(array_map(['AnalystGraphDocumentTool', 'originKey'], $node['origins']), true);
                $nodes[] = $node;
                continue;
            }
            $kept = $storedAnswers[$uuid];
            foreach (['x', 'y', 'pinned', 'collapsed'] as $field) {
                unset($kept[$field]);
                if (array_key_exists($field, $node)) {
                    $kept[$field] = $node[$field];
                }
            }
            $known = array_flip(array_map(['AnalystGraphDocumentTool', 'originKey'], $kept['origins']));
            $kept['_new'] = [];
            foreach ($node['origins'] as $origin) {
                $originKey = AnalystGraphDocumentTool::originKey($origin);
                if (!isset($known[$originKey]) && count($kept['origins']) < AnalystGraphDocumentTool::MAX_ANSWER_ORIGINS) {
                    $kept['origins'][] = $origin;
                    $kept['_new'][$originKey] = true;
                    if (!in_array($origin['module'], $kept['modules'], true)) {
                        $kept['modules'][] = $origin['module'];
                    }
                }
            }
            $nodes[] = $kept;
        }
        $putBack = [];
        foreach ($storedAnswers as $uuid => $node) {
            if (!isset($incomingAnswers[$uuid]) && !isset($seenStored[$uuid])) {
                $nodes[] = $node;
                $putBack[AnalystGraphDocumentTool::nodeKey($node)] = true;
            }
        }
        if (!empty($putBack) && !empty($stored['groups'])) {
            $incoming['groups'] = $this->groupsForWrite($user, $incoming['groups'] ?? [], $stored, $putBack, $nodes);
        }

        $attributeOrigins = $newAttributeOrigins = [];
        foreach ($nodes as $node) {
            if (!AnalystGraphDocumentTool::isAnswer($node)) {
                continue;
            }
            foreach ($node['origins'] as $origin) {
                list($type, $uuid) = explode(':', $origin['node'], 2);
                if ($type === 'Attribute') {
                    $attributeOrigins[$uuid] = true;
                    if (isset($node['_new'][AnalystGraphDocumentTool::originKey($origin)])) {
                        $newAttributeOrigins[$uuid] = true;
                    }
                }
            }
        }
        $readable = [];
        if (!empty($newAttributeOrigins)) {
            $readable = array_flip(array_map('strtolower', $this->model('CollectionElement')->readableUuids($user, 'Attribute', array_map('strval', array_keys($newAttributeOrigins)))));
        }
        $existing = [];
        if (!empty($attributeOrigins)) {
            // Soft-deleted attributes count: they can be restored
            $existing = array_flip(array_map('strtolower', $this->model('MispAttribute')->find('column', [
                'conditions' => ['Attribute.uuid' => array_map('strval', array_keys($attributeOrigins))],
                'fields' => ['Attribute.uuid'],
            ])));
        }

        do {
            $inDocument = [];
            foreach ($nodes as $node) {
                if (AnalystGraphDocumentTool::isAnswer($node)) {
                    $inDocument[$node['uuid']] = true;
                }
            }
            $changed = false;
            foreach ($nodes as $i => $node) {
                if (!AnalystGraphDocumentTool::isAnswer($node)) {
                    continue;
                }
                $origins = [];
                $alive = false;
                foreach ($node['origins'] as $origin) {
                    list($type, $uuid) = explode(':', $origin['node'], 2);
                    $new = isset($node['_new'][AnalystGraphDocumentTool::originKey($origin)]);
                    if ($type === 'Value') {
                        $live = true;
                    } elseif ($type === 'Attribute') {
                        $live = isset($existing[$uuid]);
                        if ($new && !isset($readable[$uuid])) {
                            continue;
                        }
                    } else {
                        $live = isset($inDocument[$uuid]);
                        if ($new && !$live) {
                            continue;
                        }
                    }
                    $origins[] = $origin;
                    $alive = $alive || $live;
                }
                if (!$alive) {
                    unset($nodes[$i]);
                    $changed = true;
                    continue;
                }
                if (count($origins) !== count($node['origins'])) {
                    $nodes[$i]['origins'] = $origins;
                    $changed = true;
                }
            }
        } while ($changed);

        foreach ($nodes as $i => $node) {
            unset($nodes[$i]['_new']);
        }
        return AnalystGraphDocumentTool::withNodes($incoming, array_values($nodes));
    }

    /**
     * The groups a write stores, with the answers it put back in their stored
     * group: one the writer was shown follows where the write puts its other
     * members, one they were not shown stays as stored, less the members the
     * write groups elsewhere or leaves out.
     *
     * @param array $user The writer
     * @param array $groups The write's groups, normalised
     * @param array $stored The stored document, decoded
     * @param array $putBack Keys of the answers put back, as keys
     * @param array $nodes The nodes the write stores
     * @return array
     */
    private function groupsForWrite(array $user, array $groups, array $stored, array $putBack, array $nodes)
    {
        $shown = [];
        $view = AnalystGraphDocumentTool::withNodes($stored, $this->visibleNodes($user, $stored['nodes'] ?? []));
        foreach ($view['groups'] as $group) {
            $shown += array_flip($group['members']);
        }
        $grouped = [];
        foreach ($groups as $i => $group) {
            $grouped += array_fill_keys($group['members'], $i);
        }
        $present = array_flip(array_map(['AnalystGraphDocumentTool', 'nodeKey'], $nodes));
        foreach ($stored['groups'] as $group) {
            $members = $group['members'] ?? [];
            $back = array_values(array_intersect($members, array_keys($putBack)));
            if (empty($back)) {
                continue;
            }
            $others = array_diff($members, $back);
            if (!empty(array_intersect_key($shown, array_flip($others)))) {
                foreach ($others as $key) {
                    if (isset($grouped[$key])) {
                        $groups[$grouped[$key]]['members'] = array_merge($groups[$grouped[$key]]['members'], $back);
                        break;
                    }
                }
                continue;
            }
            $group['members'] = array_values(array_filter($members, function ($key) use ($putBack, $present, $grouped) {
                return isset($putBack[$key]) || (isset($present[$key]) && !isset($grouped[$key]));
            }));
            if (count($group['members']) >= 2) {
                $grouped += array_fill_keys($group['members'], count($groups));
                $groups[] = $group;
            }
        }
        return $groups;
    }

    /**
     * How many nodes of each graph the user may read: the only count of a
     * graph's nodes a user is ever shown.
     *
     * @param array $user
     * @param array $contents key => stored document, encoded or decoded
     * @return array key => int
     */
    public function visibleCounts(array $user, array $contents)
    {
        $lists = [];
        foreach ($contents as $key => $content) {
            $document = is_array($content) ? $content : json_decode((string)$content, true);
            $lists[$key] = is_array($document['nodes'] ?? null) ? $document['nodes'] : [];
        }
        return array_map('count', $this->visibleNodeLists($user, $lists));
    }

    /**
     * Give each graph a `target`: its type and uuid, and the id and label of
     * the record when the user can read it. An unreadable target keeps only
     * what the graph itself says.
     *
     * @param array $user
     * @param array $graphs Graph rows, unwrapped
     * @return array
     */
    public function labelTargets(array $user, array $graphs)
    {
        $uuidsByType = [];
        foreach ($graphs as $graph) {
            $uuidsByType[$graph['object_type']][] = strtolower($graph['object_uuid']);
        }
        $found = [];
        foreach ($uuidsByType as $type => $uuids) {
            $found[$type] = $this->targetRecords($user, $type, array_values(array_unique($uuids)));
        }
        foreach ($graphs as &$graph) {
            $type = $graph['object_type'];
            $uuid = strtolower($graph['object_uuid']);
            $graph['target'] = [
                'type' => $type,
                'uuid' => $uuid,
                'id' => $found[$type][$uuid]['id'] ?? null,
                'label' => $found[$type][$uuid]['label'] ?? null,
            ];
        }
        unset($graph);
        return $graphs;
    }

    /**
     * @return array lowercase uuid => {id, label}
     */
    private function targetRecords(array $user, $type, array $uuids)
    {
        $out = [];
        switch ($type) {
            case 'Event':
                $rows = $this->model('Event')->fetchSimpleEvents($user, [
                    'conditions' => ['Event.uuid' => $uuids],
                ]);
                foreach ($rows as $row) {
                    $out[strtolower($row['Event']['uuid'])] = ['id' => (int)$row['Event']['id'], 'label' => $row['Event']['info']];
                }
                break;
            case 'GalaxyCluster':
                $rows = $this->model('GalaxyCluster')->fetchGalaxyClusters($user, [
                    'conditions' => ['GalaxyCluster.uuid' => $uuids],
                    'fields' => ['GalaxyCluster.id', 'GalaxyCluster.uuid', 'GalaxyCluster.value'],
                    'contain' => [],
                ]);
                foreach ($rows as $row) {
                    $out[strtolower($row['GalaxyCluster']['uuid'])] = ['id' => (int)$row['GalaxyCluster']['id'], 'label' => $row['GalaxyCluster']['value']];
                }
                break;
            case 'Collection':
                $Collection = $this->model('Collection');
                $rows = $Collection->find('all', [
                    'conditions' => ['AND' => [['Collection.uuid' => $uuids], $Collection->buildConditions($user['id'])]],
                    'fields' => ['Collection.id', 'Collection.uuid', 'Collection.name'],
                    'recursive' => -1,
                ]);
                foreach ($rows as $row) {
                    $out[strtolower($row['Collection']['uuid'])] = ['id' => (int)$row['Collection']['id'], 'label' => $row['Collection']['name']];
                }
                break;
        }
        return $out;
    }

    private function uuidsByType(array $nodes)
    {
        $uuids = array_fill_keys(AnalystGraphDocumentTool::NODE_TYPES, []);
        foreach ($nodes as $node) {
            $uuids[$node['type']][] = $node['uuid'];
        }
        return $uuids;
    }

    /**
     * @return array in document order
     */
    private function objects(array $user, array $uuids)
    {
        if (empty($uuids)) {
            return [];
        }
        $found = $this->model('MispObject')->fetchGraphObjects($user, ['Object.uuid' => $uuids]);
        return $this->inOrder($found, $uuids);
    }

    private function attributes(array $user, array $uuids)
    {
        if (empty($uuids)) {
            return [];
        }
        $found = [];
        foreach ($this->model('MispAttribute')->fetchGraphAttributes($user, ['Attribute.uuid' => $uuids]) as $attribute) {
            $found[$attribute['uuid']] = $attribute;
        }
        return $this->inOrder($found, $uuids);
    }

    private function clusters(array $user, array $uuids)
    {
        if (empty($uuids)) {
            return [];
        }
        $rows = $this->model('GalaxyCluster')->fetchGalaxyClusters($user, [
            'conditions' => ['GalaxyCluster.uuid' => $uuids],
            'fields' => [
                'GalaxyCluster.id', 'GalaxyCluster.uuid', 'GalaxyCluster.tag_name',
                'GalaxyCluster.value', 'GalaxyCluster.type', 'GalaxyCluster.description',
                'GalaxyCluster.distribution', 'GalaxyCluster.deleted',
            ],
            'contain' => ['Galaxy' => ['fields' => ['Galaxy.id', 'Galaxy.name', 'Galaxy.type', 'Galaxy.icon', 'Galaxy.namespace']]],
        ]);
        $found = [];
        foreach ($rows as $row) {
            $found[$row['GalaxyCluster']['uuid']] = $row['GalaxyCluster'] + ['Galaxy' => $row['Galaxy'] ?? []];
        }
        return $this->inOrder($found, $uuids);
    }

    /**
     * Cards for the graph's Event nodes and for the events its records sit
     * in, keyed by event id.
     */
    private function events(array $user, array $uuids, array $objects, array $attributes)
    {
        $ids = [];
        if (!empty($uuids)) {
            $ids = array_values($this->model('Event')->find('list', [
                'conditions' => ['Event.uuid' => $uuids],
                'fields' => ['Event.uuid', 'Event.id'],
                'recursive' => -1,
            ]));
        }
        foreach (array_merge($objects, $attributes) as $record) {
            $ids[] = $record['event_id'];
        }
        $ids = array_values(array_unique(array_map('strval', $ids)));
        return $this->model('Event')->correlatedEventCards($user, $ids);
    }

    /**
     * @param array $byUuid Records keyed by uuid, as stored
     * @param array $uuids Lowercase, in document order
     * @return array
     */
    private function inOrder(array $byUuid, array $uuids)
    {
        $lower = [];
        foreach ($byUuid as $uuid => $record) {
            $lower[strtolower($uuid)] = $record;
        }
        $out = [];
        foreach ($uuids as $uuid) {
            if (isset($lower[$uuid])) {
                $out[] = $lower[$uuid];
            }
        }
        return $out;
    }

    /**
     * The edges among the drawn nodes, each with an id that names it the
     * same way on every load and on every instance.
     *
     * @return array
     */
    private function edges(array $user, array $eventUuids, array $objects,
        array $attributes, array $clusters, array $values, array $events, array $answers
    ) {
        $keys = [];
        foreach ($eventUuids as $uuid) {
            $keys['Event:' . $uuid] = true;
        }
        $objectUuidById = [];
        $ends = [];
        foreach ($objects as $object) {
            $uuid = strtolower($object['uuid']);
            $objectUuidById[$object['id']] = $uuid;
            $keys['Object:' . $uuid] = true;
            foreach ($object['Attribute'] as $attribute) {
                $ends[strtolower($attribute['uuid'])] = $attribute;
            }
        }
        foreach ($attributes as $attribute) {
            $ends[strtolower($attribute['uuid'])] = $attribute;
        }
        foreach (array_keys($ends) as $uuid) {
            $keys['Attribute:' . $uuid] = true;
        }
        $clusterByTag = [];
        foreach ($clusters as $cluster) {
            $keys['GalaxyCluster:' . strtolower($cluster['uuid'])] = true;
            $clusterByTag[$cluster['tag_name']] = strtolower($cluster['uuid']);
        }
        foreach ($values as $value) {
            $keys['Value:' . $value['uuid']] = true;
        }

        $edges = [];
        $add = function (array $edge) use (&$edges) {
            $edges[$edge['id']] = $edge;
        };

        foreach ($this->objectReferences($objectUuidById, $keys) as $edge) {
            $add($edge);
        }
        foreach ($this->relationships($user, $keys) as $edge) {
            $add($edge);
        }

        $eventNodes = array_flip($eventUuids);
        $eventUuidById = [];
        foreach ($events as $id => $card) {
            $eventUuidById[$id] = strtolower($card['uuid']);
        }
        $inEvent = function ($record, $type) use ($eventUuidById, $eventNodes, $add) {
            $eventUuid = $eventUuidById[$record['event_id']] ?? null;
            if ($eventUuid !== null && isset($eventNodes[$eventUuid])) {
                $uuid = strtolower($record['uuid']);
                $add([
                    'id' => 'in-event:' . $uuid,
                    'kind' => 'in-event',
                    'from' => $type . ':' . $uuid,
                    'to' => 'Event:' . $eventUuid,
                ]);
            }
        };
        foreach ($objects as $object) {
            $inEvent($object, 'Object');
        }
        foreach ($attributes as $attribute) {
            $uuid = strtolower($attribute['uuid']);
            if (!empty($attribute['object_id']) && isset($objectUuidById[$attribute['object_id']])) {
                $add([
                    'id' => 'contains:' . $uuid,
                    'kind' => 'contains',
                    'from' => 'Object:' . $objectUuidById[$attribute['object_id']],
                    'to' => 'Attribute:' . $uuid,
                ]);
            } else {
                $inEvent($attribute, 'Attribute');
            }
        }

        $tagged = function ($type, $uuid, $clusterUuid, $label) use ($add) {
            $add([
                'id' => 'tagged:' . $uuid . '>' . $clusterUuid,
                'kind' => 'tag',
                'from' => $type . ':' . $uuid,
                'to' => 'GalaxyCluster:' . $clusterUuid,
                'label' => $label,
            ]);
        };
        $drawnClusters = array_flip($clusterByTag);
        foreach ($events as $card) {
            $eventUuid = strtolower($card['uuid']);
            if (!isset($eventNodes[$eventUuid])) {
                continue;
            }
            foreach ($card['Galaxy'] as $galaxy) {
                foreach ($galaxy['GalaxyCluster'] as $cluster) {
                    $clusterUuid = strtolower($cluster['uuid']);
                    if (isset($drawnClusters[$clusterUuid])) {
                        $tagged('Event', $eventUuid, $clusterUuid, null);
                    }
                }
            }
        }
        foreach ($ends as $uuid => $attribute) {
            foreach ($attribute['Tag'] ?? [] as $tag) {
                if (isset($clusterByTag[$tag['name']])) {
                    $tagged('Attribute', $uuid, $clusterByTag[$tag['name']], $tag['relationship_type'] ?? null);
                }
            }
        }

        foreach ($this->clusterRelations($user, array_keys($drawnClusters)) as $edge) {
            $add($edge);
        }

        $valueUuids = [];
        foreach ($values as $value) {
            $valueUuids[mb_strtolower($value['value'])][] = $value['uuid'];
        }
        if (!empty($valueUuids)) {
            foreach ($ends as $uuid => $attribute) {
                foreach ($this->valueParts($attribute) as $part) {
                    foreach ($valueUuids[mb_strtolower($part)] ?? [] as $valueUuid) {
                        $add([
                            'id' => 'value:' . $valueUuid . '>' . $uuid,
                            'kind' => 'value',
                            'from' => 'Value:' . $valueUuid,
                            'to' => 'Attribute:' . $uuid,
                        ]);
                    }
                }
            }
        }

        foreach ($answers as $answer) {
            $keys['ModuleAnswer:' . $answer['uuid']] = true;
        }
        foreach ($answers as $answer) {
            foreach ($answer['origins'] as $origin) {
                if (!isset($keys[$origin['node']])) {
                    continue;
                }
                $add([
                    'id' => 'enrichment:' . $origin['node'] . '>' . $answer['uuid'] . ':' . $origin['module'],
                    'kind' => 'enrichment',
                    'from' => $origin['node'],
                    'to' => 'ModuleAnswer:' . $answer['uuid'],
                    'label' => $origin['module'],
                    'module' => $origin['module'],
                ]);
            }
        }
        return array_values($edges);
    }

    /**
     * The values of these answers that MISP holds where the user can see
     * them: the "already in MISP" chips, recomputed for each reader.
     *
     * @param array $user
     * @param array $nodes Visible nodes
     * @return string[]
     */
    public function knownAnswerValues(array $user, array $nodes)
    {
        $answers = $this->answersOf($nodes);
        if (empty($answers)) {
            return [];
        }
        return $this->model('ValueIntelligence')->knownAnswerValues($user, array_column($answers, 'content'));
    }

    /**
     * @param array $nodes
     * @return array The module answers among them
     */
    private function answersOf(array $nodes)
    {
        return array_values(array_filter($nodes, ['AnalystGraphDocumentTool', 'isAnswer']));
    }

    /**
     * Live references from the drawn objects to drawn objects or attributes.
     * A reference belongs to its source object's event, so a readable source
     * makes it readable.
     */
    private function objectReferences(array $objectUuidById, array $keys)
    {
        if (empty($objectUuidById)) {
            return [];
        }
        $targets = [];
        foreach (array_keys($keys) as $key) {
            list($type, $uuid) = explode(':', $key, 2);
            if ($type === 'Object' || $type === 'Attribute') {
                $targets[] = $uuid;
            }
        }
        $rows = $this->model('ObjectReference')->find('all', [
            'conditions' => [
                'ObjectReference.object_id' => array_map('strval', array_keys($objectUuidById)),
                'ObjectReference.referenced_uuid' => $targets,
                'ObjectReference.deleted' => 0,
            ],
            'fields' => [
                'ObjectReference.uuid', 'ObjectReference.object_id',
                'ObjectReference.referenced_uuid', 'ObjectReference.referenced_type',
                'ObjectReference.relationship_type',
            ],
            'recursive' => -1,
        ]);
        $edges = [];
        foreach ($rows as $row) {
            $reference = $row['ObjectReference'];
            $to = ((int)$reference['referenced_type'] === 1 ? 'Object:' : 'Attribute:') . strtolower($reference['referenced_uuid']);
            if (!isset($keys[$to])) {
                continue;
            }
            $edges[] = [
                'id' => 'object-reference:' . $reference['uuid'],
                'kind' => 'object-reference',
                'from' => 'Object:' . $objectUuidById[$reference['object_id']],
                'to' => $to,
                'label' => $reference['relationship_type'],
                'uuid' => $reference['uuid'],
            ];
        }
        return $edges;
    }

    /**
     * Analyst-data relationships the user may read with both ends drawn.
     */
    private function relationships(array $user, array $keys)
    {
        $uuids = [];
        foreach (array_keys($keys) as $key) {
            $uuids[] = explode(':', $key, 2)[1];
        }
        $uuids = array_values(array_unique($uuids));
        if (empty($uuids)) {
            return [];
        }
        $relationship = $this->model('Relationship');
        $conditions = [
            'Relationship.object_uuid' => $uuids,
            'Relationship.related_object_uuid' => $uuids,
        ];
        $acl = $relationship->buildConditions($user);
        if (!empty($acl)) {
            $conditions['AND'][] = $acl;
        }
        $rows = $relationship->find('all', [
            'conditions' => $conditions,
            'fields' => [
                'Relationship.uuid', 'Relationship.object_uuid', 'Relationship.object_type',
                'Relationship.related_object_uuid', 'Relationship.related_object_type',
                'Relationship.relationship_type', 'Relationship.authors',
                'Relationship.orgc_uuid', 'Relationship.distribution',
            ],
            'recursive' => -1,
            'callbacks' => false,
        ]);
        $edges = [];
        foreach ($rows as $row) {
            $r = $row['Relationship'];
            $from = $r['object_type'] . ':' . strtolower($r['object_uuid']);
            $to = $r['related_object_type'] . ':' . strtolower($r['related_object_uuid']);
            if (!isset($keys[$from], $keys[$to])) {
                continue;
            }
            $edges[] = [
                'id' => 'relationship:' . $r['uuid'],
                'kind' => 'relationship',
                'from' => $from,
                'to' => $to,
                'label' => $r['relationship_type'],
                'uuid' => $r['uuid'],
                'authors' => $r['authors'],
                'orgc_uuid' => $r['orgc_uuid'],
                'distribution' => $r['distribution'],
            ];
        }
        return $edges;
    }

    /**
     * Relations the user may read between drawn clusters. A relation has no
     * uuid, so its ends and type name it.
     */
    private function clusterRelations(array $user, array $clusterUuids)
    {
        if (count($clusterUuids) < 2) {
            return [];
        }
        $rows = $this->model('GalaxyClusterRelation')->fetchRelations($user, [
            'conditions' => [
                'GalaxyClusterRelation.galaxy_cluster_uuid' => $clusterUuids,
                'GalaxyClusterRelation.referenced_galaxy_cluster_uuid' => $clusterUuids,
            ],
        ]);
        $edges = [];
        foreach ($rows as $row) {
            $relation = $row['GalaxyClusterRelation'];
            $from = strtolower($relation['galaxy_cluster_uuid']);
            $to = strtolower($relation['referenced_galaxy_cluster_uuid']);
            // Joins two clusters sharing a uuid across galaxies, drawn as one node.
            if ($from === $to) {
                continue;
            }
            $type = $relation['referenced_galaxy_cluster_type'];
            $edges[] = [
                'id' => 'cluster-relation:' . $from . '>' . $to . ':' . $type,
                'kind' => 'cluster-relation',
                'from' => 'GalaxyCluster:' . $from,
                'to' => 'GalaxyCluster:' . $to,
                'label' => $type,
            ];
        }
        return $edges;
    }

    /**
     * The halves a value page matches an attribute on: value1 and value2.
     *
     * @param array $attribute
     * @return string[]
     */
    private function valueParts(array $attribute)
    {
        if (isset($attribute['value1'])) {
            $parts = [$attribute['value1'], $attribute['value2'] ?? ''];
        } else {
            $parts = strpos($attribute['type'] ?? '', '|') !== false
                ? explode('|', (string)$attribute['value'], 2)
                : [(string)($attribute['value'] ?? '')];
        }
        return array_values(array_filter(array_map('strval', $parts), 'strlen'));
    }
}
