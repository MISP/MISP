<?php
/**
 * The document an analyst graph stores in its `content` column: which records
 * it shows and where they sit, never copies of them and no edges of its own.
 * The one exception is a module answer, which has no record behind it and is
 * kept whole, with the nodes it was asked about as its origins.
 *
 *     {
 *       "version": 1,
 *       "nodes": [{"type": "Attribute", "uuid": "…", "x": 120, "y": -40, "pinned": true},
 *                 {"type": "Value", "sha256": "…", "value": "8.8.8.8"},
 *                 {"type": "ModuleAnswer", "uuid": "…", "module": "dns", "modules": ["dns"],
 *                  "origins": [{"node": "Attribute:…", "module": "dns", "type": "domain",
 *                               "value": "example.com", "ran_at": 1791100000}],
 *                  "content": {"kind": "attribute", "type": "ip-dst", "value": "203.0.113.7", …}}],
 *       "groups": [{"title": "C2", "members": ["Attribute:<uuid>", "Value:<sha256>"], "x": 0, "y": 0}],
 *       "hidden_edges": ["relationship:<uuid>"],
 *       "view": {"layout": "force", "zoom": 1.0, "center": [0, 0], "rules": {"neighbours": false}},
 *       "notes": [{"id": "…", "content": "Markdown", "x": 0, "y": 0, "width": 220, "height": 160,
 *                  "color": "#FDE68A", "surface": "jewel", "node": "Attribute:<uuid>"}]
 *     }
 *
 * A note is anchored to a node by its key, or to an edge by its id; `notes`
 * is left out while there are none.
 */
class AnalystGraphDocumentTool
{
    const VERSION = 1;
    const ANSWER = 'ModuleAnswer';
    const NODE_TYPES = ['Event', 'Attribute', 'Object', 'GalaxyCluster', 'Value', self::ANSWER];
    const ORIGIN_TYPES = ['Attribute', 'Value', self::ANSWER];
    const MAX_NODES = 2000;
    const MAX_BYTES = 16777216;
    const MAX_VALUE_BYTES = 1024;
    const MAX_EDGE_ID_LENGTH = 255;
    const MAX_LAYOUT_LENGTH = 32;
    const MAX_TITLE_LENGTH = 255;
    const MAX_RULES = 32;
    const SUMMARY_LIST_LIMIT = 100;
    const MAX_NOTES = 500;
    const MAX_NOTE_BYTES = 65535;
    const NOTE_SURFACES = ['jewel', 'terminal'];
    const NOTE_ID_PATTERN = '/^[A-Za-z0-9_\-]{1,64}$/';
    const NOTE_COLOR_PATTERN = '/^#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i';

    /** MISP's own attribute value limit: what MISP could not store, a graph cannot keep. */
    const MAX_ANSWER_STRING_BYTES = 65535;
    const MAX_ANSWER_ORIGINS = 50;
    const MAX_ANSWER_ATTRIBUTES = 500;
    const ANSWER_KINDS = ['attribute', 'object', 'element'];

    const UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';
    const SHA256_PATTERN = '/^[0-9a-f]{64}$/i';
    /** Fixed forever: two instances agree on an answer's uuid only while this does. */
    const ANSWER_NAMESPACE = '6f3c2a8e-1d4b-5e7f-9a0c-3b8d2e4f6a1c';
    // No dot: the name is read back inside a configuration path
    const MODULE_PATTERN = '/^[A-Za-z0-9_\-]{1,128}$/';

    /** What a save request carries besides its document. */
    const REQUEST_OVERHEAD = 65536;

    /**
     * What a client may save: the node cap, and the bytes a document can
     * reach before PHP refuses the request that carries it, which on stock
     * settings is well under the document cap.
     *
     * @return array {nodes, bytes, document_bytes}
     */
    public static function limits()
    {
        $bytes = self::MAX_BYTES;
        $post = self::iniBytes(ini_get('post_max_size'));
        if ($post > 0) {
            $bytes = min($bytes, max(0, $post - self::REQUEST_OVERHEAD));
        }
        return ['nodes' => self::MAX_NODES, 'bytes' => $bytes, 'document_bytes' => self::MAX_BYTES];
    }

    /**
     * @param string|false $value A php.ini size, such as 8M
     * @return int Bytes; 0 for no limit
     */
    public static function iniBytes($value)
    {
        $value = trim((string)$value);
        if ($value === '' || !preg_match('/^(\d+)\s*([kmg]?)$/i', $value, $m)) {
            return 0;
        }
        $bytes = (int)$m[1];
        switch (strtolower($m[2])) {
            case 'g':
                $bytes *= 1024;
                // no break
            case 'm':
                $bytes *= 1024;
                // no break
            case 'k':
                $bytes *= 1024;
        }
        return $bytes;
    }

    /**
     * @return array
     */
    public static function emptyDocument()
    {
        return [
            'version' => self::VERSION,
            'nodes' => [],
            'groups' => [],
            'hidden_edges' => [],
            'view' => [],
        ];
    }

    /**
     * Validate a document and bring it to its stored form: keys it does not
     * define are dropped, node uuids are lowercased, and a Value node's SHA-256
     * is recomputed from its literal.
     *
     * @param array|string|null $content
     * @return array [array|null $document, string[] $errors]
     */
    public static function normalise($content)
    {
        if (is_string($content)) {
            $content = json_decode($content, true);
            if (!is_array($content)) {
                return [null, [__('The workspace document is not valid JSON.')]];
            }
        }
        if (!is_array($content)) {
            return [null, [__('The workspace document must be an object.')]];
        }

        $errors = [];
        $version = $content['version'] ?? self::VERSION;
        if ($version !== self::VERSION) {
            $errors[] = __('Unsupported workspace document version.');
        }

        $nodes = $content['nodes'] ?? [];
        if (!self::isList($nodes)) {
            $errors[] = __('nodes must be a list.');
            $nodes = [];
        }
        if (count($nodes) > self::MAX_NODES) {
            $errors[] = __('A workspace holds at most %s nodes.', self::MAX_NODES);
            $nodes = [];
        }
        $document = self::emptyDocument();
        $seen = [];
        foreach ($nodes as $i => $node) {
            $nodeErrors = [];
            $node = self::normaliseNode($node, $nodeErrors);
            foreach ($nodeErrors as $error) {
                $errors[] = sprintf('nodes[%s]: %s', $i, $error);
            }
            if ($node === null) {
                continue;
            }
            $key = self::nodeKey($node);
            if (isset($seen[$key])) {
                $errors[] = sprintf('nodes[%s]: %s', $i, __('duplicate of nodes[%s].', $seen[$key]));
                continue;
            }
            $seen[$key] = $i;
            $document['nodes'][] = $node;
        }

        $groups = $content['groups'] ?? [];
        if (!self::isList($groups)) {
            $errors[] = __('groups must be a list.');
            $groups = [];
        }
        $document['groups'] = self::normaliseGroups($groups, $seen, $errors);

        $hiddenEdges = $content['hidden_edges'] ?? [];
        if (!self::isList($hiddenEdges)) {
            $errors[] = __('hidden_edges must be a list.');
            $hiddenEdges = [];
        }
        foreach ($hiddenEdges as $i => $edgeId) {
            if (!is_string($edgeId) || $edgeId === '' || strlen($edgeId) > self::MAX_EDGE_ID_LENGTH) {
                $errors[] = sprintf('hidden_edges[%s]: %s', $i, __('must be a non-empty string of at most %s characters.', self::MAX_EDGE_ID_LENGTH));
                continue;
            }
            $document['hidden_edges'][] = $edgeId;
        }
        $document['hidden_edges'] = array_values(array_unique($document['hidden_edges']));

        $view = $content['view'] ?? [];
        if (!is_array($view) || (!empty($view) && self::isList($view))) {
            $errors[] = __('view must be an object.');
            $view = [];
        }
        $document['view'] = self::normaliseView($view, $errors);

        $notes = $content['notes'] ?? [];
        if (!self::isList($notes)) {
            $errors[] = __('notes must be a list.');
            $notes = [];
        }
        if (count($notes) > self::MAX_NOTES) {
            $errors[] = __('A workspace holds at most %s notes.', self::MAX_NOTES);
            $notes = [];
        }
        $notes = self::normaliseNotes($notes, $errors);
        if (!empty($notes)) {
            $document['notes'] = $notes;
        }

        if (!empty($errors)) {
            return [null, $errors];
        }
        if (strlen(self::encode($document)) > self::MAX_BYTES) {
            return [null, [__('A workspace document is at most %s bytes.', self::MAX_BYTES)]];
        }
        return [$document, []];
    }

    /**
     * @param array $document
     * @return string
     */
    public static function encode(array $document)
    {
        $document['view'] = (object)($document['view'] ?? []);
        return json_encode($document, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION);
    }

    /**
     * Stored content as the API returns it, `view` kept an object when empty.
     *
     * @param string $content
     * @return array|null
     */
    public static function decode($content)
    {
        $document = is_string($content) ? json_decode($content, true) : null;
        if (!is_array($document)) {
            return null;
        }
        $document['view'] = (object)($document['view'] ?? []);
        return $document;
    }

    /**
     * The columns derived from stored content.
     *
     * @param string $content
     * @return array
     */
    public static function measure($content)
    {
        return [
            'content_size' => strlen($content),
            'node_count' => count(self::storedNodeKeys($content)),
        ];
    }

    /**
     * @param array $node A normalised node
     * @return string
     */
    public static function nodeKey(array $node)
    {
        return $node['type'] . ':' . self::addressOf($node);
    }

    /**
     * @param array $node A normalised node
     * @return string|null Its uuid, or a Value node's SHA-256
     */
    public static function addressOf(array $node)
    {
        return $node[$node['type'] === 'Value' ? 'sha256' : 'uuid'] ?? null;
    }

    /**
     * The SHA-256 a Value node is named by.
     *
     * @param string $value
     * @return string Lowercase hex
     */
    public static function valueAddress($value)
    {
        return hash('sha256', trim((string)$value));
    }

    /**
     * Append nodes to a stored document. A node already in it is reported
     * present, one that is malformed or that the document has no room for is
     * refused.
     *
     * @param array $document A stored document, decoded
     * @param array $items Nodes, as the document holds them
     * @return array [array $document, array $report]
     */
    public static function addNodes(array $document, array $items)
    {
        $report = ['added' => [], 'present' => [], 'refused' => []];
        $nodes = isset($document['nodes']) && is_array($document['nodes']) ? $document['nodes'] : [];
        $seen = array_flip(self::nodeKeysOf($nodes));
        foreach (array_values($items) as $i => $item) {
            if (is_array($item) && ($item['type'] ?? null) === self::ANSWER) {
                $report['refused'][] = ['index' => $i, 'error' => __('A module answer is kept by saving the workspace, not added to it.')];
                continue;
            }
            $errors = [];
            $node = self::normaliseNode($item, $errors);
            if ($node === null) {
                $report['refused'][] = ['index' => $i, 'error' => implode(' ', $errors)];
                continue;
            }
            $key = self::nodeKey($node);
            if (isset($seen[$key])) {
                $report['present'][] = $key;
                continue;
            }
            if (count($nodes) >= self::MAX_NODES) {
                $report['refused'][] = ['index' => $i, 'error' => __('A workspace holds at most %s nodes.', self::MAX_NODES)];
                continue;
            }
            $seen[$key] = true;
            $nodes[] = $node;
            $report['added'][] = $key;
        }
        $document['nodes'] = $nodes;
        return [$document, $report];
    }

    /**
     * The document holding only these nodes: a group keeps the members still
     * in it, and goes with fewer than two.
     *
     * @param array $document A stored document, decoded
     * @param array $nodes Nodes of that document
     * @return array
     */
    public static function withNodes(array $document, array $nodes)
    {
        $document['nodes'] = $nodes;
        $present = array_flip(self::nodeKeysOf($nodes));
        $groups = [];
        foreach ($document['groups'] ?? [] as $group) {
            $members = array_values(array_filter($group['members'] ?? [], function ($key) use ($present) {
                return isset($present[$key]);
            }));
            if (count($members) < 2) {
                continue;
            }
            $group['members'] = $members;
            $groups[] = $group;
        }
        $document['groups'] = $groups;
        return $document;
    }

    /**
     * Remove nodes from a stored document, named as nodes or as the
     * `Type:uuid` keys addNodes() reports. A node in $kept stays, reported
     * absent like one the document does not hold.
     *
     * @param array $document A stored document, decoded
     * @param array $items
     * @param array $kept `Type:uuid` => true
     * @return array [array $document, array $report]
     */
    public static function removeNodes(array $document, array $items, array $kept = [])
    {
        $report = ['removed' => [], 'absent' => [], 'refused' => []];
        $wanted = [];
        foreach (array_values($items) as $i => $item) {
            $key = self::keyOf($item);
            if ($key === null) {
                $report['refused'][] = ['index' => $i, 'error' => __('not a node.')];
                continue;
            }
            $wanted[$key] = true;
        }
        $remaining = [];
        foreach ($document['nodes'] ?? [] as $node) {
            $key = self::nodeKeysOf([$node])[0] ?? null;
            if ($key !== null && isset($wanted[$key]) && !isset($kept[$key])) {
                $report['removed'][] = $key;
                unset($wanted[$key]);
                continue;
            }
            $remaining[] = $node;
        }
        $report['absent'] = array_keys($wanted);
        return [self::withNodes($document, $remaining), $report];
    }

    /**
     * @param mixed $item A node, or a `Type:uuid` key
     * @return string|null
     */
    private static function keyOf($item)
    {
        if (is_string($item)) {
            $parts = explode(':', $item, 2);
            $item = count($parts) === 2 ? ['type' => $parts[0], 'uuid' => $parts[1]] : null;
        }
        if (!is_array($item) || !isset($item['type']) || !in_array($item['type'], self::NODE_TYPES, true)) {
            return null;
        }
        if ($item['type'] === 'Value' && isset($item['value']) && is_scalar($item['value'])) {
            $value = trim((string)$item['value']);
            return $value === '' ? null : 'Value:' . self::valueAddress($value);
        }
        $address = $item['type'] === 'Value' ? ($item['sha256'] ?? $item['uuid'] ?? null) : ($item['uuid'] ?? null);
        $pattern = $item['type'] === 'Value' ? self::SHA256_PATTERN : self::UUID_PATTERN;
        if (!is_string($address) || !preg_match($pattern, $address)) {
            return null;
        }
        return $item['type'] . ':' . strtolower($address);
    }

    /**
     * What the audit log records for a content change in place of the
     * document: node counts, and which nodes came and went.
     *
     * @param string|null $old Stored content before the change
     * @param string|null $new Stored content after it
     * @return array
     */
    public static function summariseChange($old, $new)
    {
        $newKeys = self::storedNodeKeys($new);
        $summary = [
            'node_count' => count($newKeys),
            'content_size' => strlen((string)$new),
        ];
        $newNotes = self::storedNotes($new);
        if ($old === null) {
            if (!empty($newNotes)) {
                $summary['note_count'] = count($newNotes);
            }
            return $summary;
        }
        $oldKeys = self::storedNodeKeys($old);
        $summary['node_count'] = [count($oldKeys), count($newKeys)];
        $summary['content_size'] = [strlen($old), strlen((string)$new)];
        $lists = ['nodes_added' => array_diff($newKeys, $oldKeys), 'nodes_removed' => array_diff($oldKeys, $newKeys)];
        $oldNotes = self::storedNotes($old);
        if (!empty($oldNotes) || !empty($newNotes)) {
            $summary['note_count'] = [count($oldNotes), count($newNotes)];
            // What a note says and what it is about; moving or restyling it is layout
            $edited = array_filter(array_intersect_key($newNotes, $oldNotes), function ($note, $id) use ($oldNotes) {
                foreach (['content', 'node', 'edge'] as $field) {
                    if (($note[$field] ?? null) !== ($oldNotes[$id][$field] ?? null)) {
                        return true;
                    }
                }
                return false;
            }, ARRAY_FILTER_USE_BOTH);
            $lists += [
                'notes_added' => array_keys(array_diff_key($newNotes, $oldNotes)),
                'notes_removed' => array_keys(array_diff_key($oldNotes, $newNotes)),
                'notes_edited' => array_keys($edited),
            ];
        }
        foreach ($lists as $field => $keys) {
            $keys = array_map('strval', array_values($keys));
            $summary[$field . '_count'] = count($keys);
            $summary[$field] = array_slice($keys, 0, self::SUMMARY_LIST_LIMIT);
        }
        return $summary;
    }

    /**
     * @param string|null $content
     * @return array Note id => note
     */
    private static function storedNotes($content)
    {
        $document = is_string($content) ? json_decode($content, true) : null;
        $notes = [];
        foreach (is_array($document) && is_array($document['notes'] ?? null) ? $document['notes'] : [] as $note) {
            if (is_array($note) && isset($note['id']) && is_string($note['id'])) {
                $notes[$note['id']] = $note;
            }
        }
        return $notes;
    }

    /**
     * @param string|null $content
     * @return string[]
     */
    private static function storedNodeKeys($content)
    {
        $document = is_string($content) ? json_decode($content, true) : null;
        if (!is_array($document) || !isset($document['nodes']) || !is_array($document['nodes'])) {
            return [];
        }
        return self::nodeKeysOf($document['nodes']);
    }

    /**
     * @param array $nodes
     * @return string[]
     */
    private static function nodeKeysOf(array $nodes)
    {
        $keys = [];
        foreach ($nodes as $node) {
            if (isset($node['type']) && self::addressOf($node) !== null) {
                $keys[] = self::nodeKey($node);
            }
        }
        return $keys;
    }

    /**
     * @param mixed $node
     * @param string[] $errors
     * @return array|null
     */
    private static function normaliseNode($node, array &$errors)
    {
        if (!is_array($node)) {
            $errors[] = __('must be an object.');
            return null;
        }
        $type = $node['type'] ?? null;
        if (!is_string($type) || !in_array($type, self::NODE_TYPES, true)) {
            $errors[] = __('unknown node type.');
            return null;
        }
        $normalised = ['type' => $type];
        if ($type === self::ANSWER) {
            $answer = self::normaliseAnswer($node, $errors);
            if ($answer === null) {
                return null;
            }
            $normalised += $answer;
        } elseif ($type === 'Value') {
            $value = isset($node['value']) && is_scalar($node['value']) ? trim((string)$node['value']) : '';
            if ($value === '') {
                $errors[] = __('a Value node needs a value.');
                return null;
            }
            if (strlen($value) > self::MAX_VALUE_BYTES) {
                $errors[] = __('a Value node holds at most %s bytes.', self::MAX_VALUE_BYTES);
                return null;
            }
            $normalised['sha256'] = self::valueAddress($value);
            $normalised['value'] = $value;
        } else {
            $uuid = $node['uuid'] ?? null;
            if (!is_string($uuid) || !preg_match(self::UUID_PATTERN, $uuid)) {
                $errors[] = __('invalid uuid.');
                return null;
            }
            $normalised['uuid'] = strtolower($uuid);
        }
        foreach (['x', 'y'] as $axis) {
            if (!isset($node[$axis])) {
                continue;
            }
            if (!self::isFiniteNumber($node[$axis])) {
                $errors[] = __('%s must be a number.', $axis);
                return null;
            }
            $normalised[$axis] = $node[$axis];
        }
        foreach (['pinned', 'collapsed', 'pulled_out'] as $flag) {
            if (!empty($node[$flag])) {
                $normalised[$flag] = true;
            }
        }
        if ($type === self::ANSWER) {
            // The answer itself last, so a reader of the document finds the layout first
            foreach (['module', 'modules', 'origins', 'content'] as $field) {
                $value = $normalised[$field];
                unset($normalised[$field]);
                $normalised[$field] = $value;
            }
        }
        return $normalised;
    }

    /**
     * @param array $node
     * @return bool
     */
    public static function isAnswer(array $node)
    {
        return ($node['type'] ?? null) === self::ANSWER;
    }

    /**
     * The uuid an answer is stored under, derived from what it says: an
     * attribute or an untyped element by its type and value, so the same value
     * from several modules is one node; an object by its module, name and
     * attributes.
     *
     * @param array $content A normalised answer content
     * @param string $module
     * @return string
     */
    public static function answerUuid(array $content, $module)
    {
        if ($content['kind'] === 'object') {
            $triples = [];
            foreach ($content['attributes'] as $attribute) {
                $triples[] = [$attribute['relation'], $attribute['type'], $attribute['value']];
            }
            sort($triples);
            $hash = hash('sha256', json_encode([$content['name'], $triples], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
            return self::uuidV5('enr-obj:' . $module . ':' . $hash);
        }
        $type = $content['kind'] === 'element' ? $content['types'][0] : $content['type'];
        return self::answerUuidFor($type, $content['value']);
    }

    /**
     * The uuid of the attribute or element answer holding this value.
     *
     * @param string $type
     * @param string $value
     * @return string
     */
    public static function answerUuidFor($type, $value)
    {
        return self::uuidV5('enr:' . $type . ':' . $value);
    }

    /**
     * An RFC 4122 version 5 uuid, in the namespace answers are named in.
     *
     * @param string $name
     * @return string
     */
    public static function uuidV5($name)
    {
        $hash = sha1(hex2bin(str_replace('-', '', self::ANSWER_NAMESPACE)) . $name);
        return sprintf(
            '%s-%s-%04x-%04x-%s',
            substr($hash, 0, 8),
            substr($hash, 8, 4),
            (hexdec(substr($hash, 12, 4)) & 0x0fff) | 0x5000,
            (hexdec(substr($hash, 16, 4)) & 0x3fff) | 0x8000,
            substr($hash, 20, 12)
        );
    }

    /**
     * An origin's identity within its answer: the node asked and the module
     * that answered.
     *
     * @param array $origin
     * @return string
     */
    public static function originKey(array $origin)
    {
        return $origin['node'] . '|' . $origin['module'];
    }

    /**
     * A document without its module answers, as sync carries it.
     *
     * @param array $document Decoded
     * @return array
     */
    public static function withoutAnswers(array $document)
    {
        if (isset($document['nodes']) && is_array($document['nodes'])) {
            $document = self::withNodes($document, array_values(array_filter($document['nodes'], function ($node) {
                return !is_array($node) || !self::isAnswer($node);
            })));
        }
        return $document;
    }

    /**
     * A document whose module answers are reduced to their keys, for what
     * runs outside the graph's audience.
     *
     * @param array $document Decoded
     * @return array
     */
    public static function answersAsKeys(array $document)
    {
        if (isset($document['nodes']) && is_array($document['nodes'])) {
            foreach ($document['nodes'] as $i => $node) {
                if (is_array($node) && self::isAnswer($node)) {
                    $document['nodes'][$i] = ['type' => self::ANSWER, 'uuid' => $node['uuid'] ?? null];
                }
            }
        }
        return $document;
    }

    /**
     * @param array $node
     * @param string[] $errors
     * @return array|null module, modules, origins, content and the derived uuid
     */
    private static function normaliseAnswer(array $node, array &$errors)
    {
        $module = $node['module'] ?? null;
        if (!is_string($module) || !preg_match(self::MODULE_PATTERN, $module)) {
            $errors[] = __('an answer names the module it came from.');
            return null;
        }
        $content = isset($node['content']) && is_array($node['content'])
            ? self::normaliseContent($node['content'], $errors)
            : null;
        if ($content === null) {
            if (empty($errors)) {
                $errors[] = __('an answer needs its content.');
            }
            return null;
        }
        $uuid = self::answerUuid($content, $module);

        $modules = [$module];
        $listed = $node['modules'] ?? [];
        if (!self::isList($listed)) {
            $errors[] = __('modules must be a list.');
            return null;
        }
        foreach ($listed as $name) {
            if (!is_string($name) || !preg_match(self::MODULE_PATTERN, $name)) {
                $errors[] = __('modules must be module names.');
                return null;
            }
            $modules[] = $name;
        }
        $modules = array_values(array_unique($modules));
        if (count($modules) > self::MAX_ANSWER_ORIGINS) {
            $errors[] = __('an answer names at most %s modules.', self::MAX_ANSWER_ORIGINS);
            return null;
        }

        $origins = $node['origins'] ?? null;
        if (!self::isList($origins) || empty($origins)) {
            $errors[] = __('an answer needs the origins it was asked about.');
            return null;
        }
        if (count($origins) > self::MAX_ANSWER_ORIGINS) {
            $errors[] = __('an answer has at most %s origins.', self::MAX_ANSWER_ORIGINS);
            return null;
        }
        $kept = [];
        foreach ($origins as $i => $origin) {
            $origin = self::normaliseOrigin($origin, $error);
            if ($origin === null) {
                $errors[] = sprintf('origins[%s]: %s', $i, $error);
                return null;
            }
            // A module can return the value it was asked about
            if ($origin['node'] === self::ANSWER . ':' . $uuid) {
                continue;
            }
            $kept[self::originKey($origin)] = $kept[self::originKey($origin)] ?? $origin;
        }
        if (empty($kept)) {
            $errors[] = __('an answer needs the origins it was asked about.');
            return null;
        }
        return [
            'uuid' => $uuid,
            'module' => $module,
            'modules' => $modules,
            'origins' => array_values($kept),
            'content' => $content,
        ];
    }

    /**
     * @param mixed $origin
     * @param string|null $error
     * @return array|null
     */
    private static function normaliseOrigin($origin, &$error)
    {
        $error = null;
        if (!is_array($origin)) {
            $error = __('must be an object.');
            return null;
        }
        $node = $origin['node'] ?? null;
        $parts = is_string($node) ? explode(':', $node, 2) : [null];
        $type = $parts[0];
        if (!in_array($type, self::ORIGIN_TYPES, true)) {
            $error = __('an origin is an attribute, a value or another answer.');
            return null;
        }
        $module = $origin['module'] ?? null;
        if (!is_string($module) || !preg_match(self::MODULE_PATTERN, $module)) {
            $error = __('an origin names the module asked.');
            return null;
        }
        $asked = [];
        foreach (['type', 'value'] as $field) {
            $asked[$field] = self::answerString($origin[$field] ?? null, false, $error);
            if ($asked[$field] === null) {
                $error = __('%s: %s', $field, $error);
                return null;
            }
        }
        $ranAt = $origin['ran_at'] ?? null;
        if (is_string($ranAt) && ctype_digit($ranAt)) {
            $ranAt = (int)$ranAt;
        }
        if (!is_int($ranAt) || $ranAt < 0) {
            $error = __('ran_at must be a timestamp.');
            return null;
        }
        if ($type === 'Attribute') {
            $uuid = $parts[1] ?? null;
            if (!is_string($uuid) || !preg_match(self::UUID_PATTERN, $uuid)) {
                $error = __('invalid uuid.');
                return null;
            }
            $uuid = strtolower($uuid);
        } elseif ($type === 'Value') {
            if (trim($asked['value']) === '') {
                $error = __('a Value origin needs a value.');
                return null;
            }
            $uuid = self::valueAddress($asked['value']);
        } else {
            $uuid = self::answerUuidFor($asked['type'], $asked['value']);
        }
        return [
            'node' => $type . ':' . $uuid,
            'module' => $module,
            'type' => $asked['type'],
            'value' => $asked['value'],
            'ran_at' => $ranAt,
        ];
    }

    /**
     * @param array $content
     * @param string[] $errors
     * @return array|null
     */
    private static function normaliseContent(array $content, array &$errors)
    {
        $kind = $content['kind'] ?? null;
        if (!in_array($kind, self::ANSWER_KINDS, true)) {
            $errors[] = __('content.kind is attribute, object or element.');
            return null;
        }
        $error = null;
        if ($kind === 'attribute') {
            $attribute = self::normaliseAnswerAttribute($content, false, $error);
            if ($attribute === null) {
                $errors[] = 'content.' . $error;
                return null;
            }
            return ['kind' => 'attribute'] + $attribute;
        }
        if ($kind === 'element') {
            $types = $content['types'] ?? null;
            if (!self::isList($types) || empty($types) || count($types) > self::MAX_ANSWER_ORIGINS) {
                $errors[] = __('content.types must be a list of at most %s types.', self::MAX_ANSWER_ORIGINS);
                return null;
            }
            foreach ($types as $i => $type) {
                $types[$i] = self::answerString($type, false, $error);
                if ($types[$i] === null) {
                    $errors[] = 'content.types: ' . $error;
                    return null;
                }
            }
            $value = self::answerString($content['value'] ?? null, false, $error);
            if ($value === null) {
                $errors[] = 'content.value: ' . $error;
                return null;
            }
            return ['kind' => 'element', 'types' => array_values(array_unique($types)), 'value' => $value];
        }
        $object = ['kind' => 'object'];
        foreach (['name' => false, 'meta_category' => true, 'description' => true, 'comment' => true] as $field => $optional) {
            $object[$field] = self::answerString($content[$field] ?? ($optional ? '' : null), $optional, $error);
            if ($object[$field] === null) {
                $errors[] = 'content.' . $field . ': ' . $error;
                return null;
            }
        }
        $attributes = $content['attributes'] ?? [];
        if (!self::isList($attributes) || count($attributes) > self::MAX_ANSWER_ATTRIBUTES) {
            $errors[] = __('content.attributes must be a list of at most %s attributes.', self::MAX_ANSWER_ATTRIBUTES);
            return null;
        }
        $object['attributes'] = [];
        foreach ($attributes as $i => $attribute) {
            $attribute = is_array($attribute) ? self::normaliseAnswerAttribute($attribute, true, $error) : null;
            if ($attribute === null) {
                $errors[] = sprintf('content.attributes[%s].%s', $i, $error ?? __('must be an object.'));
                return null;
            }
            $object['attributes'][] = $attribute;
        }
        return $object;
    }

    /**
     * @param array $attribute
     * @param bool $withRelation
     * @param string|null $error
     * @return array|null
     */
    private static function normaliseAnswerAttribute(array $attribute, $withRelation, &$error)
    {
        $fields = ($withRelation ? ['relation' => true] : []) + [
            'type' => false,
            'value' => false,
            'category' => true,
            'comment' => true,
        ];
        $out = [];
        foreach ($fields as $field => $optional) {
            $out[$field] = self::answerString($attribute[$field] ?? ($optional ? '' : null), $optional, $error);
            if ($out[$field] === null) {
                $error = $field . ': ' . $error;
                return null;
            }
        }
        $out['to_ids'] = !empty($attribute['to_ids']);
        return $out;
    }

    /**
     * @param mixed $value
     * @param bool $mayBeEmpty
     * @param string|null $error
     * @return string|null
     */
    private static function answerString($value, $mayBeEmpty, &$error)
    {
        if ($value === null && $mayBeEmpty) {
            $value = '';
        }
        if (!is_string($value) && !is_int($value) && !is_float($value)) {
            $error = __('must be a string.');
            return null;
        }
        $value = (string)$value;
        if ($value === '' && !$mayBeEmpty) {
            $error = __('must not be empty.');
            return null;
        }
        if (strlen($value) > self::MAX_ANSWER_STRING_BYTES) {
            $error = __('at most %s bytes.', self::MAX_ANSWER_STRING_BYTES);
            return null;
        }
        return $value;
    }

    /**
     * @param array $groups
     * @param array $nodeKeys The document's node keys, as keys
     * @param string[] $errors
     * @return array
     */
    private static function normaliseGroups(array $groups, array $nodeKeys, array &$errors)
    {
        $normalised = [];
        $groupOf = [];
        foreach ($groups as $i => $group) {
            if (!is_array($group) || (!empty($group) && self::isList($group))) {
                $errors[] = sprintf('groups[%s]: %s', $i, __('must be an object.'));
                continue;
            }
            $members = $group['members'] ?? null;
            if (!self::isList($members)) {
                $errors[] = sprintf('groups[%s]: %s', $i, __('members must be a list.'));
                continue;
            }
            $keys = [];
            foreach ($members as $member) {
                $key = self::keyOf($member);
                if ($key === null) {
                    $errors[] = sprintf('groups[%s]: %s', $i, __('a member is not a node.'));
                    continue 2;
                }
                if (isset($groupOf[$key])) {
                    $errors[] = sprintf('groups[%s]: %s', $i, __('%s is already in groups[%s].', $key, $groupOf[$key]));
                    continue 2;
                }
                if (isset($nodeKeys[$key])) {
                    $keys[$key] = true;
                }
            }
            $out = [];
            if (isset($group['title'])) {
                $title = is_string($group['title']) ? trim($group['title']) : null;
                if ($title === null || mb_strlen($title) > self::MAX_TITLE_LENGTH) {
                    $errors[] = sprintf('groups[%s]: %s', $i, __('title must be a string of at most %s characters.', self::MAX_TITLE_LENGTH));
                    continue;
                }
                if ($title !== '') {
                    $out['title'] = $title;
                }
            }
            $out['members'] = array_keys($keys);
            foreach (['x', 'y'] as $axis) {
                if (!isset($group[$axis])) {
                    continue;
                }
                if (!self::isFiniteNumber($group[$axis])) {
                    $errors[] = sprintf('groups[%s]: %s', $i, __('%s must be a number.', $axis));
                    continue 2;
                }
                $out[$axis] = $group[$axis];
            }
            if (!empty($group['open'])) {
                $out['open'] = true;
            }
            if (count($keys) < 2) {
                continue;
            }
            foreach ($out['members'] as $key) {
                $groupOf[$key] = $i;
            }
            $normalised[] = $out;
        }
        return $normalised;
    }

    /**
     * @param array $notes
     * @param string[] $errors
     * @return array
     */
    private static function normaliseNotes(array $notes, array &$errors)
    {
        $normalised = [];
        $seen = [];
        foreach ($notes as $i => $note) {
            $error = null;
            $note = self::normaliseNote($note, $error);
            if ($note === null) {
                $errors[] = sprintf('notes[%s]: %s', $i, $error);
                continue;
            }
            if (isset($seen[$note['id']])) {
                $errors[] = sprintf('notes[%s]: %s', $i, __('duplicate of notes[%s].', $seen[$note['id']]));
                continue;
            }
            $seen[$note['id']] = $i;
            $normalised[] = $note;
        }
        return $normalised;
    }

    /**
     * @param mixed $note
     * @param string|null $error
     * @return array|null
     */
    private static function normaliseNote($note, &$error)
    {
        if (!is_array($note) || (!empty($note) && self::isList($note))) {
            $error = __('must be an object.');
            return null;
        }
        $id = $note['id'] ?? null;
        if (!is_string($id) || !preg_match(self::NOTE_ID_PATTERN, $id)) {
            $error = __('id must be at most 64 letters, digits, dashes or underscores.');
            return null;
        }
        $content = $note['content'] ?? '';
        if (!is_string($content) || strlen($content) > self::MAX_NOTE_BYTES) {
            $error = __('content must be a string of at most %s bytes.', self::MAX_NOTE_BYTES);
            return null;
        }
        $out = ['id' => $id, 'content' => $content];
        foreach (['x', 'y', 'width', 'height'] as $field) {
            if (!isset($note[$field])) {
                continue;
            }
            $value = $note[$field];
            $isSize = $field === 'width' || $field === 'height';
            if (!self::isFiniteNumber($value) || ($isSize && $value <= 0)) {
                $error = $isSize ? __('%s must be a positive number.', $field) : __('%s must be a number.', $field);
                return null;
            }
            $out[$field] = $value;
        }
        if (isset($note['color'])) {
            if (!is_string($note['color']) || !preg_match(self::NOTE_COLOR_PATTERN, $note['color'])) {
                $error = __('color must be a hex colour.');
                return null;
            }
            $out['color'] = $note['color'];
        }
        if (isset($note['surface'])) {
            if (!in_array($note['surface'], self::NOTE_SURFACES, true)) {
                $error = __('surface is one of %s.', implode(', ', self::NOTE_SURFACES));
                return null;
            }
            $out['surface'] = $note['surface'];
        }
        if (isset($note['node'], $note['edge'])) {
            $error = __('a note is anchored to a node or to an edge, not both.');
            return null;
        }
        if (isset($note['node'])) {
            $nodeErrors = [];
            $key = is_array($note['node']) ? self::normaliseNode($note['node'], $nodeErrors) : self::keyOf($note['node']);
            if (is_array($key)) {
                $key = self::nodeKey($key);
            }
            if (!is_string($key)) {
                $error = __('node is not a node.');
                return null;
            }
            $out['node'] = $key;
        } elseif (isset($note['edge'])) {
            $edge = $note['edge'];
            if (!is_string($edge) || $edge === '' || strlen($edge) > self::MAX_EDGE_ID_LENGTH) {
                $error = __('edge must be a non-empty string of at most %s characters.', self::MAX_EDGE_ID_LENGTH);
                return null;
            }
            $out['edge'] = $edge;
        }
        return $out;
    }

    /**
     * @param array $view
     * @param string[] $errors
     * @return array
     */
    private static function normaliseView(array $view, array &$errors)
    {
        $normalised = [];
        if (isset($view['layout'])) {
            if (is_string($view['layout']) && $view['layout'] !== '' && strlen($view['layout']) <= self::MAX_LAYOUT_LENGTH) {
                $normalised['layout'] = $view['layout'];
            } else {
                $errors[] = __('view.layout must be a short string.');
            }
        }
        if (isset($view['zoom'])) {
            if (self::isFiniteNumber($view['zoom']) && $view['zoom'] > 0) {
                $normalised['zoom'] = $view['zoom'];
            } else {
                $errors[] = __('view.zoom must be a positive number.');
            }
        }
        if (isset($view['center'])) {
            $center = $view['center'];
            if (is_array($center) && self::isList($center) && count($center) === 2 && self::isFiniteNumber($center[0]) && self::isFiniteNumber($center[1])) {
                $normalised['center'] = [$center[0], $center[1]];
            } else {
                $errors[] = __('view.center must be [x, y].');
            }
        }
        if (isset($view['rules'])) {
            $rules = $view['rules'];
            $valid = is_array($rules) && (empty($rules) || !self::isList($rules)) && count($rules) <= self::MAX_RULES;
            foreach ($valid ? $rules : [] as $id => $enabled) {
                if (!is_string($id) || strlen($id) > self::MAX_LAYOUT_LENGTH || !is_bool($enabled)) {
                    $valid = false;
                }
            }
            if (!$valid) {
                $errors[] = __('view.rules must map at most %s rule ids to true or false.', self::MAX_RULES);
            } elseif (!empty($rules)) {
                $normalised['rules'] = $rules;
            }
        }
        return $normalised;
    }

    private static function isFiniteNumber($value)
    {
        return (is_int($value) || is_float($value)) && is_finite($value);
    }

    private static function isList($value)
    {
        return is_array($value) && ($value === [] || array_keys($value) === range(0, count($value) - 1));
    }
}
