<?php
App::uses('AppController', 'Controller');
App::uses('AnalystGraphDocumentTool', 'Tools');
App::uses('FileAccessTool', 'Tools');
App::uses('JsonTool', 'Tools');
App::uses('MispTheme', 'MispTheme');
App::uses('Graph', 'Model');

/**
 * The actions only an analyst graph has. Creating, editing, viewing and
 * deleting one go through AnalystDataController with the type `Graph`.
 */
class AnalystGraphsController extends AppController
{
    public $components = ['Session', 'RequestHandler'];

    public $uses = ['Graph', 'AnalystGraphData'];

    /** The only theme that carries the graph page. */
    const THEME = 'Overmind';

    /** Collections offered as a fork's other target. */
    const FORK_COLLECTIONS = 50;

    /** Graphs a record's Graphs card lists. */
    const TARGET_LIMIT = 100;

    /** Graphs one export or one import carries. */
    const TRANSFER_LIMIT = 100;

    /** Bytes an imported file may hold. */
    const IMPORT_MAX_BYTES = 67108864;

    public function beforeFilter()
    {
        parent::beforeFilter();
        // Posted as hand-built JSON by the graph host, with the CSRF token
        // in the X-CSRF-Token header.
        $this->_csrfTokenHeaderOnly(['save', 'addNodes', 'removeNodes', 'fork', 'active', 'edges']);
    }

    public function beforeRender()
    {
        parent::beforeRender();
        if (!MispTheme::carries($this->theme, 'AnalystGraphs')) {
            $this->theme = self::THEME;
            $this->viewClass = 'Theme';
        }
    }

    /**
     * The graph's own page: the explorer at full size, where its editors
     * save it and everyone else may fork it.
     *
     * @param string $uuid
     */
    public function view($uuid)
    {
        $this->request->allowMethod(['get']);
        $user = $this->Auth->user();
        $graph = $this->__fetchGraph($uuid);
        $summary = $this->Graph->summaries($user, ['Graph.id' => $graph['Graph']['id']], ['parents' => true])[0];

        $canAnalyst = !empty($user['Role']['perm_site_admin'])
            || (!empty($user['Role']['perm_add']) && !empty($user['Role']['perm_analyst_data']));
        $this->set('graph', $summary);
        $this->set('canEdit', !empty($summary['_canEdit']));
        $this->set('canFork', $canAnalyst);
        $labels = ClassRegistry::init('AnalystProfile')->pivotLabels($user);
        $canGraph = $this->ACL->canUserAccess($user, 'analystData', 'add')
            && $this->ACL->canUserAccess($user, 'analystGraphs', 'save');
        $this->set('explorer', [
            'canEdit' => !empty($user['Role']['perm_site_admin']) || !empty($user['Role']['perm_modify']),
            'canAnalyst' => $canAnalyst,
            'analystSharing' => $canAnalyst ? $this->__analystSharing($user, $summary) : null,
            'graphSharing' => $canGraph ? $this->__analystSharing($user, $summary) : null,
            'labelPlan' => $labels['plan'],
            'permitted' => $labels['permitted'],
        ]);
        $this->set('forkTargets', $canAnalyst ? $this->__forkTargets($user, $summary) : []);
        $this->set('intelGraphShown', $summary['uuid']);
        if (!empty($summary['target']['label'])) {
            $this->set('intelGraphPage', [
                'type' => $summary['target']['type'],
                'uuid' => $summary['target']['uuid'],
                'label' => $summary['target']['label'],
            ]);
        }
        $this->set('title_for_layout', $summary['name']);
    }
    /**
     * The graph "Add to graph" feeds. POST `{graph_uuid}` sets it to a graph
     * the user may edit, or clears it with null.
     */
    public function active()
    {
        $this->request->allowMethod(['get', 'post']);
        $user = $this->Auth->user();
        if ($this->request->is('get')) {
            return $this->RestResponse->viewData(['Graph' => $this->Graph->activeFor($user)], 'json');
        }
        $input = $this->__input();
        if (!array_key_exists('graph_uuid', $input) || ($input['graph_uuid'] !== null && !is_string($input['graph_uuid']))) {
            throw new BadRequestException(__('Name the graph to add to, or null for none.'));
        }
        $graph = null;
        if ($input['graph_uuid'] !== null) {
            $graph = $this->__fetchEditableGraph($input['graph_uuid']);
            $graph = $this->Graph->summaries($user, ['Graph.id' => $graph['Graph']['id']])[0];
        }
        if (!$this->Graph->storeActive($user, $graph ? $graph['uuid'] : null)) {
            throw new InternalErrorException(__('The active graph could not be saved.'));
        }
        return $this->RestResponse->viewData(['Graph' => $graph], 'json');
    }

    /**
     * The graphs hung off one record that the user may read, newest first,
     * and the user's active graph.
     *
     * @param string $type
     * @param string $uuid
     */
    public function forTarget($type, $uuid)
    {
        $this->request->allowMethod(['get']);
        if (!in_array($type, Graph::VALID_TARGETS, true) || !Validation::uuid($uuid)) {
            throw new NotFoundException(__('Invalid target.'));
        }
        $user = $this->Auth->user();
        // Stored as each creator spelled it
        $spellings = array_values(array_unique([$uuid, strtolower($uuid), strtoupper($uuid)]));
        $graphs = $this->Graph->summaries($user, [
            'Graph.object_type' => $type,
            'Graph.object_uuid' => $spellings,
        ], ['targets' => false, 'parents' => true, 'limit' => self::TARGET_LIMIT]);
        $active = $this->ACL->canUserAccess($user, 'analystGraphs', 'active')
            ? $this->Graph->activeFor($user, false)
            : null;
        return $this->RestResponse->viewData([
            'Graph' => $graphs,
            'active' => $active ? $active['uuid'] : null,
        ], 'json');
    }

    /**
     * The organisation's graphs the user may edit, newest first, without
     * their documents; `?scope=mine` keeps those the user authored.
     */
    public function editable()
    {
        $this->request->allowMethod(['get']);
        $user = $this->Auth->user();
        $active = $this->Graph->activeFor($user, false);
        $mine = ($this->request->query['scope'] ?? null) === 'mine';
        return $this->RestResponse->viewData([
            'Graph' => $this->Graph->editableBy($user, $mine),
            'active' => $active ? $active['uuid'] : null,
        ], 'json');
    }

    /**
     * The graph as the user sees it: its document, the records of the nodes
     * they may read and the edges between them.
     *
     * @param string $uuid
     */
    public function data($uuid)
    {
        $this->request->allowMethod(['get']);
        $graph = $this->__fetchGraph($uuid);
        $document = json_decode($graph['Graph']['content'], true) ?: AnalystGraphDocumentTool::emptyDocument();
        unset($graph['Graph']['content']);
        $payload = $this->AnalystGraphData->resolve($this->Auth->user(), $document);
        // Counted and measured as this user sees it (G6)
        $graph['Graph']['node_count'] = $payload['meta']['nodes'];
        unset($graph['Graph']['content_size']);
        $payload['editable_events'] = $this->__editableEvents(array_keys((array)$payload['events']));
        $payload['known_values'] = $this->AnalystGraphData->knownAnswerValues($this->Auth->user(), $payload['document']['nodes']);
        return $this->RestResponse->viewData(['Graph' => $this->Graph->typed($graph['Graph'])] + $payload, 'json');
    }

    /**
     * The edges MISP holds between the nodes a Pivot Explorer canvas shows,
     * as a graph of them would draw them once saved.
     */
    public function edges()
    {
        $this->request->allowMethod(['post']);
        // Read-only, and asked after every landing
        $user = $this->_closeSession();
        $nodes = $this->__input()['nodes'] ?? null;
        if (!is_array($nodes)) {
            throw new BadRequestException(__('Name the nodes to join as a list.'));
        }
        list($out, $errors) = $this->AnalystGraphData->edgesBetween($user, $nodes);
        if ($out === null) {
            throw new BadRequestException(implode(' ', array_slice($errors, 0, 10)));
        }
        return $this->RestResponse->viewData($out, 'json');
    }

    /**
     * What a thumbnail of the graph draws for this user (AnalystGraphData::thumbnail).
     *
     * @param string $uuid
     */
    public function thumbnail($uuid)
    {
        $this->request->allowMethod(['get']);
        // Read-only, and asked for several at a time: it leaves the session
        // as it found it
        $user = $this->_closeSession();
        $graph = $this->__fetchGraph($uuid);
        $document = json_decode($graph['Graph']['content'], true) ?: AnalystGraphDocumentTool::emptyDocument();
        return $this->RestResponse->viewData([
            'uuid' => $graph['Graph']['uuid'],
            'revision' => (int)$graph['Graph']['revision'],
        ] + $this->AnalystGraphData->thumbnail($user, $document), 'json');
    }

    /**
     * Replace the document, unless the graph was saved since the revision the
     * client started from.
     *
     * @param string $uuid
     */
    public function save($uuid)
    {
        $this->request->allowMethod(['post', 'put']);
        $graph = $this->__fetchEditableGraph($uuid);
        $input = $this->__input();
        $revision = $input['revision'] ?? null;
        if (!is_int($revision) && !(is_string($revision) && ctype_digit($revision))) {
            throw new BadRequestException(__('A save names the revision it started from.'));
        }
        if (!isset($input['content']) || (!is_array($input['content']) && !is_string($input['content']))) {
            throw new BadRequestException(__('A save carries the graph document as content.'));
        }
        $content = $input['content'];
        $user = $this->Auth->user();
        $result = $this->Graph->writeContent($graph['Graph']['id'], function (array $stored) use ($content, $user) {
            return $this->Graph->contentForWrite($user, $content, $stored);
        }, (int)$revision);
        return $this->__writeResponse($graph, $result);
    }

    /**
     * Add records to the stored document, without the client loading it.
     *
     * @param string $uuid
     */
    public function addNodes($uuid)
    {
        $this->request->allowMethod(['post']);
        $graph = $this->__fetchEditableGraph($uuid);
        $items = $this->__items();
        $report = null;
        $result = $this->Graph->writeContent($graph['Graph']['id'], function (array $document) use ($items, &$report) {
            list($document, $report) = AnalystGraphDocumentTool::addNodes($document, $items);
            return empty($report['added']) ? null : $document;
        });
        return $this->__writeResponse($graph, $result, $report);
    }

    /**
     * Remove records from the stored document, as the undo of addNodes().
     *
     * @param string $uuid
     */
    public function removeNodes($uuid)
    {
        $this->request->allowMethod(['post']);
        $graph = $this->__fetchEditableGraph($uuid);
        $items = $this->__items();
        $user = $this->Auth->user();
        $report = null;
        $result = $this->Graph->writeContent($graph['Graph']['id'], function (array $document) use ($items, $user, &$report) {
            // An answer the user cannot see is not theirs to remove
            $seen = [];
            foreach ($this->AnalystGraphData->visibleNodes($user, $document['nodes'] ?? []) as $node) {
                $seen[AnalystGraphDocumentTool::nodeKey($node)] = true;
            }
            $hidden = [];
            foreach ($document['nodes'] ?? [] as $node) {
                if (AnalystGraphDocumentTool::isAnswer($node) && !isset($seen[AnalystGraphDocumentTool::nodeKey($node)])) {
                    $hidden[AnalystGraphDocumentTool::nodeKey($node)] = true;
                }
            }
            list($document, $report) = AnalystGraphDocumentTool::removeNodes($document, $items, $hidden);
            return empty($report['removed']) ? null : $document;
        });
        return $this->__writeResponse($graph, $result, $report);
    }

    /**
     * A copy of the graph owned by the user's organisation, holding the nodes
     * they can see. Its distribution is the analyst-data default.
     *
     * @param string $uuid
     */
    public function fork($uuid)
    {
        $this->request->allowMethod(['post']);
        $user = $this->Auth->user();
        $original = $this->__fetchGraph($uuid);
        $input = $this->__input();
        $document = json_decode($original['Graph']['content'], true) ?: AnalystGraphDocumentTool::emptyDocument();
        $document = $this->Graph->contentForWrite($user, $this->AnalystGraphData->documentFor($user, $document));
        $target = isset($input['target']) && is_array($input['target']) ? $input['target'] : [];
        $fork = ['Graph' => [
            'name' => isset($input['name']) && is_string($input['name']) ? $input['name'] : $original['Graph']['name'],
            'description' => $original['Graph']['description'],
            'object_uuid' => $target['uuid'] ?? $original['Graph']['object_uuid'],
            'object_type' => $target['type'] ?? $original['Graph']['object_type'],
            'content' => $document,
            'forked_from_uuid' => $original['Graph']['uuid'],
        ]];
        $this->Graph->current_user = $user;
        $this->Graph->create();
        if (!$this->Graph->save($fork)) {
            return $this->RestResponse->saveFailResponse('AnalystGraphs', 'fork', false, $this->Graph->validationErrors, 'json');
        }
        $id = $this->Graph->id;
        $created = $this->Graph->summaries($user, ['Graph.id' => $id])[0];
        $created['content'] = $this->AnalystGraphData->documentFor($user, AnalystGraphDocumentTool::decode($this->Graph->storedContents([$id])[$id]));
        return $this->RestResponse->viewData(['Graph' => $created], 'json');
    }

    /**
     * A graph, or a selection of them, as a file to import elsewhere. A graph
     * exports as analystData/view returns it, a selection as analystData/index
     * does, each holding only the nodes the user may read.
     *
     * @param string $ref A graph's uuid, or a JSON list of graph ids
     */
    public function export($ref)
    {
        $this->request->allowMethod(['get']);
        $user = $this->Auth->user();
        $single = Validation::uuid($ref);
        if ($single) {
            $conditions = ['Graph.uuid' => $ref];
        } else {
            $ids = json_decode($ref, true);
            if (!is_array($ids) || empty($ids)) {
                throw new BadRequestException(__('Name a graph, or a list of graph ids.'));
            }
            foreach ($ids as $id) {
                if (!is_int($id) && !(is_string($id) && ctype_digit($id))) {
                    throw new BadRequestException(__('Name a graph, or a list of graph ids.'));
                }
            }
            if (count($ids) > self::TRANSFER_LIMIT) {
                throw new BadRequestException(__('At most %s graphs at once.', self::TRANSFER_LIMIT));
            }
            $conditions = ['Graph.id' => array_map('strval', array_values($ids))];
        }
        $this->Graph->current_user = $user;
        $rows = $this->Graph->find('all', [
            'conditions' => ['AND' => [$conditions, $this->Graph->buildConditions($user)]],
            'contain' => ['Orgc'],
            'order' => ['Graph.id' => 'ASC'],
        ]);
        if (empty($rows)) {
            throw new NotFoundException(__('Invalid graph.'));
        }
        $graphs = $this->__exported($user, $rows);
        if ($single) {
            $payload = $graphs[0];
            $filename = 'analyst-graph-' . (trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($payload['Graph']['name'])), '-') ?: $payload['Graph']['uuid']) . '.json';
        } else {
            $payload = $graphs;
            $filename = 'analyst-graphs-' . date('Y-m-d') . '.json';
        }
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
        return $this->RestResponse->viewData($json, 'application/json', false, true, $filename);
    }

    /**
     * Graphs from an export, owned by the user's organisation. Each keeps its
     * uuid; one this instance already holds or has blocklisted is refused.
     */
    public function import()
    {
        $user = $this->Auth->user();
        if (!$this->request->is('post')) {
            if ($this->_isRest()) {
                throw new MethodNotAllowedException(__('This endpoint only accepts POST requests.'));
            }
            $this->__setImportForm($user);
            if ($this->request->is('ajax')) {
                $this->layout = false;
            }
            return;
        }
        $posted = $this->request->data;
        $form = isset($posted['Graph']['import']) && is_array($posted['Graph']['import']) ? $posted['Graph']['import'] : null;
        try {
            if ($form !== null) {
                $options = $form;
                $graphs = $this->__graphsIn(json_decode($this->__importText($form), true));
                if (isset($form['target']) && is_string($form['target']) && $form['target'] !== '') {
                    list($type, $uuid) = array_pad(explode(':', $form['target'], 2), 2, null);
                    $options['target'] = ['type' => $type, 'uuid' => $uuid];
                } else {
                    unset($options['target']);
                }
            } elseif (is_array($posted) && array_key_exists('graphs', $posted)) {
                $options = $posted;
                $graphs = $this->__graphsIn($posted['graphs']);
            } else {
                $options = [];
                $graphs = $this->__graphsIn($posted);
            }
            $report = $this->__importGraphs($user, $graphs, $options);
        } catch (BadRequestException $e) {
            if ($this->_isRest()) {
                throw $e;
            }
            $this->Flash->error($e->getMessage());
            return $this->redirect($this->referer(['controller' => 'analyst_data', 'action' => 'index', 'Graph'], true));
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($report, 'json');
        }
        return $this->__importRedirect($report);
    }

    /**
     * @param array $user
     * @param array $rows Graph rows, with their document and Orgc
     * @return array [{Graph: {...}}]
     */
    private function __exported(array $user, array $rows)
    {
        $documents = $nodes = [];
        foreach ($rows as $i => $row) {
            $documents[$i] = AnalystGraphDocumentTool::decode($row['Graph']['content']) ?: AnalystGraphDocumentTool::emptyDocument();
            $nodes[$i] = $documents[$i]['nodes'] ?? [];
        }
        $visible = $this->AnalystGraphData->visibleNodeLists($user, $nodes);
        $graphs = [];
        foreach ($rows as $i => $row) {
            $graph = $row['Graph'];
            $document = AnalystGraphDocumentTool::withNodes($documents[$i], $visible[$i]);
            $document['view'] = (object)($document['view'] ?? []);
            $graphs[] = ['Graph' => [
                'uuid' => $graph['uuid'],
                'name' => $graph['name'],
                'description' => $graph['description'],
                'authors' => $graph['authors'],
                'object_type' => $graph['object_type'],
                'object_uuid' => $graph['object_uuid'],
                'orgc_uuid' => $graph['orgc_uuid'],
                'Orgc' => [
                    'uuid' => $graph['Orgc']['uuid'] ?? $graph['orgc_uuid'],
                    'name' => $graph['Orgc']['name'] ?? null,
                ],
                'created' => $graph['created'],
                'modified' => $graph['modified'],
                'forked_from_uuid' => $graph['forked_from_uuid'],
                'content' => $document,
            ]];
        }
        return $graphs;
    }

    /**
     * The JSON the import form carries: the uploaded file, else the pasted text.
     *
     * @param array $form
     * @return string
     * @throws BadRequestException
     */
    private function __importText(array $form)
    {
        $file = $form['file'] ?? null;
        if (is_array($file) && ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
            if ($file['error'] !== UPLOAD_ERR_OK || empty($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
                throw new BadRequestException(__('The file could not be uploaded.'));
            }
            if ($file['size'] > self::IMPORT_MAX_BYTES) {
                throw new BadRequestException(__('The file is larger than %s MB.', self::IMPORT_MAX_BYTES / 1048576));
            }
            return FileAccessTool::readFromFile($file['tmp_name'], $file['size']);
        }
        $text = isset($form['json']) && is_string($form['json']) ? trim($form['json']) : '';
        if ($text === '') {
            throw new BadRequestException(__('Choose an exported file, or paste its contents.'));
        }
        if (strlen($text) > self::IMPORT_MAX_BYTES) {
            throw new BadRequestException(__('The text is larger than %s MB.', self::IMPORT_MAX_BYTES / 1048576));
        }
        return $text;
    }

    /**
     * The graphs of an export, either shape, or of a REST view or index answer.
     *
     * @param mixed $payload
     * @return array Unwrapped graphs
     * @throws BadRequestException
     */
    private function __graphsIn($payload)
    {
        if (is_array($payload) && isset($payload['Graph']) && is_array($payload['Graph'])) {
            $payload = $payload['Graph'];
        }
        if (!is_array($payload) || empty($payload)) {
            throw new BadRequestException(__('This is not an analyst graph export.'));
        }
        if (array_keys($payload) !== range(0, count($payload) - 1)) {
            $payload = [$payload];
        }
        if (count($payload) > self::TRANSFER_LIMIT) {
            throw new BadRequestException(__('At most %s graphs at once.', self::TRANSFER_LIMIT));
        }
        $graphs = [];
        foreach ($payload as $item) {
            if (is_array($item) && isset($item['Graph']) && is_array($item['Graph'])) {
                $item = $item['Graph'];
            }
            $graphs[] = is_array($item) ? $item : [];
        }
        return $graphs;
    }

    /**
     * @param array $user
     * @param array $graphs Unwrapped
     * @param array $options `target` {type, uuid}, `distribution`, `sharing_group_id`
     * @return array {imported: [summary], failed: [{index, name, errors}]}
     * @throws BadRequestException
     */
    private function __importGraphs(array $user, array $graphs, array $options)
    {
        $target = null;
        if (isset($options['target'])) {
            $target = $options['target'];
            if (!is_array($target) || !in_array($target['type'] ?? null, Graph::VALID_TARGETS, true) || !is_string($target['uuid'] ?? null) || !Validation::uuid($target['uuid'])) {
                throw new BadRequestException(__('A target is a collection, an event or a galaxy cluster, named by its uuid.'));
            }
        }
        $sharing = [];
        if (isset($options['distribution']) && $options['distribution'] !== '') {
            $sharing['distribution'] = (string)$options['distribution'];
            if ($sharing['distribution'] === '4') {
                $sharing['sharing_group_id'] = $options['sharing_group_id'] ?? null;
                if (!ClassRegistry::init('SharingGroup')->canUse($user, $sharing['sharing_group_id'])) {
                    throw new BadRequestException(__('Invalid Sharing Group or not authorised.'));
                }
            }
        }
        $imported = $failed = $ids = [];
        $this->Graph->current_user = $user;
        $blocklist = ClassRegistry::init('AnalystDataBlocklist');
        foreach ($graphs as $index => $graph) {
            $name = isset($graph['name']) && is_string($graph['name']) ? $graph['name'] : '';
            $refuse = function ($field, $message) use (&$failed, $index, $name) {
                $failed[] = ['index' => $index, 'name' => $name, 'errors' => [$field => [$message]]];
            };
            $uuid = $graph['uuid'] ?? null;
            if ($uuid !== null) {
                if (!is_string($uuid) || !Validation::uuid($uuid)) {
                    $refuse('uuid', __('Please provide a valid RFC 4122 UUID'));
                    continue;
                }
                // Stored as each creator spelled it
                $spellings = array_values(array_unique([$uuid, strtolower($uuid), strtoupper($uuid)]));
                if ($this->Graph->find('count', ['conditions' => ['Graph.uuid' => $spellings], 'callbacks' => false])) {
                    $refuse('uuid', __('A graph with this uuid already exists.'));
                    continue;
                }
                if ($blocklist->hasAny(['AnalystDataBlocklist.analyst_data_uuid' => $spellings])) {
                    $refuse('uuid', __('A graph with this uuid is blocklisted.'));
                    continue;
                }
                $uuid = strtolower($uuid);
            }
            $forkedFrom = $graph['forked_from_uuid'] ?? null;
            $record = [
                'name' => $name,
                'description' => isset($graph['description']) && is_string($graph['description']) ? $graph['description'] : null,
                'object_type' => $target['type'] ?? (is_string($graph['object_type'] ?? null) ? $graph['object_type'] : null),
                'object_uuid' => $target['uuid'] ?? (is_string($graph['object_uuid'] ?? null) ? $graph['object_uuid'] : null),
                'forked_from_uuid' => is_string($forkedFrom) && Validation::uuid($forkedFrom) ? strtolower($forkedFrom) : null,
            ] + $sharing;
            if ($uuid !== null) {
                $record['uuid'] = $uuid;
            }
            if (isset($graph['authors']) && is_string($graph['authors']) && $graph['authors'] !== '') {
                $record['authors'] = $graph['authors'];
            }
            if (array_key_exists('content', $graph)) {
                $record['content'] = $this->Graph->contentForWrite($user, $graph['content']);
            }
            if (empty($record['object_type']) || empty($record['object_uuid'])) {
                $refuse('object_uuid', __('This graph names no target; choose one to import it onto.'));
                continue;
            }
            $this->Graph->create();
            if ($this->Graph->save(['Graph' => $record])) {
                $ids[] = $this->Graph->id;
            } else {
                $failed[] = ['index' => $index, 'name' => $name, 'errors' => $this->Graph->validationErrors];
            }
        }
        if (!empty($ids)) {
            $imported = $this->Graph->summaries($user, ['Graph.id' => $ids]);
        }
        return ['imported' => $imported, 'failed' => $failed];
    }

    /**
     * After an import from the form: the graph, when it is the only one, else
     * the Graphs index.
     *
     * @param array $report __importGraphs()'s
     * @return CakeResponse
     */
    private function __importRedirect(array $report)
    {
        $imported = $report['imported'];
        if (!empty($report['failed'])) {
            $reasons = [];
            foreach ($report['failed'] as $failure) {
                $errors = Hash::flatten((array)$failure['errors']);
                $reasons[] = sprintf(
                    '%s: %s',
                    $failure['name'] !== '' ? $failure['name'] : __('Graph #%s', $failure['index'] + 1),
                    implode(' ', array_slice(array_values($errors), 0, 3))
                );
            }
            $message = empty($imported)
                ? __('No graph was imported. %s', implode(' — ', $reasons))
                : __('%s graph(s) imported, %s not. %s', count($imported), count($report['failed']), implode(' — ', $reasons));
            $this->Flash->error($message);
        } else {
            $this->Flash->success(count($imported) === 1
                ? __('Graph "%s" imported.', $imported[0]['name'])
                : __('%s graphs imported.', count($imported)));
        }
        if (count($imported) === 1 && empty($report['failed'])) {
            return $this->redirect('/analyst_graphs/view/' . $imported[0]['uuid']);
        }
        return $this->redirect(['controller' => 'analyst_data', 'action' => 'index', 'Graph']);
    }

    /**
     * What the import form offers: where the graphs can land and who sees them.
     *
     * @param array $user
     */
    private function __setImportForm(array $user)
    {
        $levels = [];
        foreach (ClassRegistry::init('Event')->distributionLevels as $level => $name) {
            if ($level <= 4) {
                $levels[$level] = $name;
            }
        }
        $this->set('distributionLevels', $levels);
        $this->set('sharingGroups', ClassRegistry::init('SharingGroup')->fetchAllAuthorised($user, 'name', 1));
        $this->set('defaultDistribution', (int)(Configure::read('MISP.default_analyst_data_distribution') ?? 1));
        $this->set('collections', $this->__orgCollections($user));
        $this->set('transferLimit', self::TRANSFER_LIMIT);
    }

    /**
     * @param string $uuid
     * @return array
     * @throws NotFoundException
     */
    private function __fetchGraph($uuid)
    {
        if (!Validation::uuid($uuid)) {
            throw new NotFoundException(__('Invalid graph.'));
        }
        $user = $this->Auth->user();
        $this->Graph->current_user = $user;
        $graph = $this->Graph->find('first', [
            'conditions' => [
                'AND' => [
                    ['Graph.uuid' => $uuid],
                    $this->Graph->buildConditions($user),
                ],
            ],
            'contain' => ['Org', 'Orgc'],
        ]);
        if (empty($graph)) {
            throw new NotFoundException(__('Invalid graph.'));
        }
        return $graph;
    }

    /**
     * @param string $uuid
     * @return array
     * @throws ForbiddenException
     */
    private function __fetchEditableGraph($uuid)
    {
        $graph = $this->__fetchGraph($uuid);
        if (empty($graph['Graph']['_canEdit'])) {
            throw new ForbiddenException(__('Only the organisation that created this graph can change it. Fork it instead.'));
        }
        return $graph;
    }

    /**
     * What a relationship drawn in the graph can be shared with, as
     * analystData/add offers it, defaulting to the graph's own distribution.
     *
     * @param array $user
     * @param array $graph Summary
     * @return array
     */
    private function __analystSharing(array $user, array $graph)
    {
        $levels = [];
        foreach (ClassRegistry::init('Event')->distributionLevels as $level => $name) {
            if ($level <= 4) {
                $levels[] = [(int)$level, $name];
            }
        }
        $sharingGroups = [];
        $authorised = ClassRegistry::init('SharingGroup')->fetchAllAuthorised($user, 'name', 1);
        asort($authorised);
        foreach ($authorised as $id => $name) {
            $sharingGroups[] = [(int)$id, $name];
        }
        return [
            'levels' => $levels,
            'sharingGroups' => $sharingGroups,
            'default' => (int)$graph['distribution'],
            'sharingGroup' => $graph['sharing_group_id'],
            'authors' => $user['email'] ?? '',
        ];
    }

    /**
     * Where a fork can land: the original's target when the user can read
     * it, then the collections their organisation created (Q8).
     *
     * @param array $user
     * @param array $graph Summary, its target labelled
     * @return array [{type, uuid, label}]
     */
    private function __forkTargets(array $user, array $graph)
    {
        $targets = [];
        if (!empty($graph['target']['label'])) {
            $targets[] = [
                'type' => $graph['target']['type'],
                'uuid' => $graph['target']['uuid'],
                'label' => $graph['target']['label'],
            ];
        }
        foreach ($this->__orgCollections($user) as $collection) {
            if (!empty($targets) && $targets[0]['uuid'] === $collection['uuid']) {
                continue;
            }
            $targets[] = $collection;
        }
        return $targets;
    }

    /**
     * The collections the user's organisation created, newest first.
     *
     * @param array $user
     * @return array [{type, uuid, label}]
     */
    private function __orgCollections(array $user)
    {
        $collections = ClassRegistry::init('Collection')->find('all', [
            'conditions' => ['Collection.orgc_id' => $user['org_id']],
            'fields' => ['Collection.uuid', 'Collection.name'],
            'order' => ['Collection.modified' => 'DESC'],
            'limit' => self::FORK_COLLECTIONS,
            'recursive' => -1,
        ]);
        $targets = [];
        foreach ($collections as $collection) {
            $targets[] = [
                'type' => 'Collection',
                'uuid' => strtolower($collection['Collection']['uuid']),
                'label' => $collection['Collection']['name'],
            ];
        }
        return $targets;
    }

    /**
     * Of these events, the ones the user may modify: where an edge drawn in
     * the graph can be an object reference.
     *
     * @param array $ids
     * @return int[]
     */
    private function __editableEvents(array $ids)
    {
        $user = $this->Auth->user();
        if (empty($ids) || (empty($user['Role']['perm_modify']) && empty($user['Role']['perm_site_admin']))) {
            return [];
        }
        $events = ClassRegistry::init('Event')->find('all', [
            'conditions' => ['Event.id' => array_map('strval', $ids)],
            'fields' => ['Event.id', 'Event.orgc_id', 'Event.user_id'],
            'recursive' => -1,
        ]);
        $editable = [];
        foreach ($events as $event) {
            if ($this->ACL->canModifyEvent($user, $event)) {
                $editable[] = (int)$event['Event']['id'];
            }
        }
        return $editable;
    }

    /**
     * @return array
     */
    private function __input()
    {
        $input = $this->request->data;
        if (!is_array($input)) {
            return [];
        }
        return isset($input['Graph']) && is_array($input['Graph']) ? $input['Graph'] : $input;
    }

    /**
     * @return array
     * @throws BadRequestException
     */
    private function __items()
    {
        $items = $this->__input()['items'] ?? null;
        if (!is_array($items) || empty($items) || array_keys($items) !== range(0, count($items) - 1)) {
            throw new BadRequestException(__('A list of items is required.'));
        }
        if (count($items) > AnalystGraphDocumentTool::MAX_NODES) {
            throw new BadRequestException(__('At most %s items at once.', AnalystGraphDocumentTool::MAX_NODES));
        }
        return $items;
    }

    /**
     * @param array $graph
     * @param array $result Graph::writeContent()'s
     * @param array|null $report What addNodes() or removeNodes() did
     * @return CakeResponse
     */
    private function __writeResponse(array $graph, array $result, $report = null)
    {
        switch ($result['status']) {
            case 'missing':
                throw new NotFoundException(__('Invalid graph.'));
            case 'conflict':
                $this->response->statusCode(409);
                $this->response->type('json');
                $this->response->body(JsonTool::encode([
                    'saved' => false,
                    'name' => __('The graph was saved since you loaded it.'),
                    'message' => __('The graph was saved since you loaded it.'),
                    'url' => $this->request->here,
                    'revision' => $result['revision'],
                ]));
                return $this->response;
            case 'invalid':
                return $this->RestResponse->saveFailResponse('AnalystGraphs', $this->request->params['action'], $graph['Graph']['id'], $result['errors'], 'json');
        }
        $id = $graph['Graph']['id'];
        $visible = $this->AnalystGraphData->visibleCounts($this->Auth->user(), $this->Graph->storedContents([$id]));
        $response = [
            'saved' => true,
            'changed' => $result['status'] === 'saved',
            'uuid' => $graph['Graph']['uuid'],
            'revision' => $result['revision'],
            'node_count' => $visible[$id] ?? 0,
        ];
        if ($result['status'] === 'saved') {
            $response['content_size'] = $result['content_size'];
            $response['modified'] = $result['modified'];
        }
        return $this->RestResponse->viewData($response + (array)$report, 'json');
    }
}
