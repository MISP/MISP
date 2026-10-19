<?php
App::uses('AppModel', 'Model');
App::uses('CakeText', 'Utility');
App::uses('Value', 'Model');
App::uses('ValueNewEventTool', 'Tools/ValueIntelligence');
App::uses('ValueTypeGuessTool', 'Tools/ValueIntelligence');

/**
 * A new event made from a value page: the value as an attribute, and the
 * enrichment findings the reader picked, read back from what their
 * organisation stored rather than from the request.
 */
class ValueNewEvent extends AppModel
{
    public $useTable = false;

    private $models = [];

    private function model($alias)
    {
        if (!isset($this->models[$alias])) {
            $this->models[$alias] = ClassRegistry::init($alias);
        }
        return $this->models[$alias];
    }

    /**
     * What the dialog draws.
     *
     * @param array $user
     * @param string $value
     * @param array $picks As ValueNewEventTool::picks() returns them
     * @return array `value`, `groups`, `count`, `missing`, `relationships`, `org`
     */
    public function forDialog(array $user, $value, array $picks)
    {
        list($found, $missing) = $this->resolve($user, $value, $picks);
        $attribute = $this->model('MispAttribute');
        $groups = [];
        foreach ($found as $fp => $finding) {
            $item = $finding['item'];
            $row = ['fp' => $fp, 'kind' => $finding['kind'], 'module' => $finding['module'], 'type' => $finding['type']];
            if ($finding['kind'] === 'object') {
                $peek = [];
                foreach ($item['attributes'] ?? [] as $a) {
                    if (mb_strlen((string)$a['value']) >= 3) {
                        $peek[] = (string)$a['value'];
                    }
                    if (count($peek) === 3) {
                        break;
                    }
                }
                $row += [
                    'name' => (string)$item['name'],
                    'meta_category' => (string)($item['meta_category'] ?? ''),
                    'attribute_count' => count($item['attributes'] ?? []),
                    'peek' => $peek,
                ];
            } else {
                $types = $finding['kind'] === 'element' ? array_values((array)$item['types']) : [(string)$item['type']];
                $categories = ValueNewEventTool::categoriesFor($types[0], $attribute->typeDefinitions, $attribute->categoryDefinitions);
                $category = $finding['kind'] === 'attribute' && in_array($item['category'] ?? null, $categories, true)
                    ? $item['category']
                    : ($categories[0] ?? '');
                $row += [
                    'value' => (string)$item['value'],
                    'types' => $types,
                    'attribute_type' => $types[0],
                    'categories' => $categories,
                    'category' => $category,
                    'to_ids' => $finding['kind'] === 'attribute'
                        ? !empty($item['to_ids'])
                        : !empty($attribute->typeDefinitions[$types[0]]['to_ids']),
                ];
            }
            if (!isset($groups[$finding['module']])) {
                $groups[$finding['module']] = ['module' => $finding['module'], 'findings' => []];
            }
            $groups[$finding['module']]['findings'][] = $row;
        }
        $valueBlock = $this->valueBlock($user, $value, $picks);
        $typeInfo = [];
        foreach ($valueBlock['types'] as $type) {
            $typeInfo[$type['type']] = ['categories' => $type['categories'], 'to_ids' => $type['to_ids']];
        }
        foreach ($groups as $group) {
            foreach ($group['findings'] as $row) {
                foreach ($row['types'] ?? [] as $type) {
                    if (!isset($typeInfo[$type])) {
                        $typeInfo[$type] = [
                            'categories' => ValueNewEventTool::categoriesFor($type, $attribute->typeDefinitions, $attribute->categoryDefinitions),
                            'to_ids' => !empty($attribute->typeDefinitions[$type]['to_ids']),
                        ];
                    }
                }
            }
        }
        return [
            'value' => $valueBlock,
            'type_info' => $typeInfo,
            'groups' => array_values($groups),
            'count' => count($found),
            'missing' => $missing,
            'relationships' => $this->relationships(),
            'org' => $user['Organisation']['name'] ?? '',
        ];
    }

    /**
     * Create the event, then land the findings in it.
     *
     * @param array $user
     * @param string $value
     * @param array $data The dialog's form: `Event`, `Value`, `Finding`
     * @return array `errors` (field => message) on a refusal; otherwise
     *   `event_id`, `saved`, `existing`, `failed`, `missing`, `message`
     */
    public function createFromDialog(array $user, $value, array $data)
    {
        $attribute = $this->model('MispAttribute');
        $eventModel = $this->model('Event');
        $event = is_array($data['Event'] ?? null) ? $data['Event'] : [];
        $seed = is_array($data['Value'] ?? null) ? $data['Value'] : [];
        $rows = is_array($data['Finding'] ?? null) ? $data['Finding'] : [];

        $picks = ValueNewEventTool::picks(array_values(array_filter($rows, 'is_array')));
        $edits = [];
        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['fp'] ?? null)) {
                $edits[strtolower($row['fp'])] = [
                    'type' => $row['attribute_type'] ?? null,
                    'category' => $row['category'] ?? null,
                    'to_ids' => !empty($row['to_ids']),
                    'relationship' => $row['relationship'] ?? null,
                ];
            }
        }

        $errors = [];
        $info = trim((string)($event['info'] ?? ''));
        if ($info === '') {
            $errors['info'] = __('Please provide a name for the event.');
        } elseif (strlen($info) > 65535) {
            $errors['info'] = __('Event info is too long.');
        }
        $date = (string)($event['date'] ?? '');
        $parsed = DateTime::createFromFormat('!Y-m-d', $date);
        if (!$parsed || $parsed->format('Y-m-d') !== $date) {
            $errors['date'] = __('Enter the event date.');
        }
        $distribution = (int)($event['distribution'] ?? 0);
        $sharingGroupId = null;
        if (!array_key_exists($distribution, $eventModel->distributionLevels)) {
            $errors['distribution'] = __('Pick a distribution.');
        } elseif ($distribution === 4) {
            $sharingGroupId = (int)($event['sharing_group_id'] ?? 0);
            if (!$this->model('SharingGroup')->canUse($user, $sharingGroupId)) {
                $errors['sharing_group_id'] = __('Pick a sharing group you may use.');
            }
        }
        $threatLevel = (int)($event['threat_level_id'] ?? 0);
        if (!$eventModel->ThreatLevel->hasAny(['ThreatLevel.id' => $threatLevel])) {
            $errors['threat_level_id'] = __('Pick a threat level.');
        }
        $analysis = (int)($event['analysis'] ?? -1);
        if (!array_key_exists($analysis, $eventModel->analysisLevels)) {
            $errors['analysis'] = __('Pick an analysis level.');
        }
        $types = array_column($this->valueBlock($user, $value, $picks)['types'], null, 'type');
        $type = (string)($seed['type'] ?? '');
        $category = (string)($seed['category'] ?? '');
        if (!isset($types[$type])) {
            $errors['value_type'] = __('This value cannot be saved as %s.', $type);
        } elseif (!in_array($category, $types[$type]['categories'], true)) {
            $errors['value_category'] = __('%s is not a category for %s.', $category, $type);
        }
        if (!empty($errors)) {
            return ['errors' => $errors];
        }

        $valueUuid = CakeText::uuid();
        $new = ['Event' => [
            'info' => $info,
            'date' => $date,
            'distribution' => $distribution,
            'threat_level_id' => $threatLevel,
            'analysis' => $analysis,
            'published' => 0,
            'Attribute' => [[
                'uuid' => $valueUuid,
                'type' => $type,
                'category' => $category,
                'value' => (string)$value,
                'to_ids' => !empty($seed['to_ids']),
                'comment' => trim((string)($seed['comment'] ?? '')),
                'distribution' => 5,
            ]],
        ]];
        if ($sharingGroupId !== null) {
            $new['Event']['sharing_group_id'] = $sharingGroupId;
        }
        $createdId = 0;
        $validationErrors = [];
        $result = $eventModel->_add($new, false, $user, 0, null, false, null, $createdId, $validationErrors);
        if ($result !== true) {
            return ['errors' => ['event' => __('The event could not be created.')]];
        }
        $eventId = (int)$createdId ?: (int)$eventModel->id;

        list($found, $missing) = $this->resolve($user, $value, $picks);
        $out = ['event_id' => $eventId, 'saved' => 0, 'existing' => 0, 'failed' => 0, 'missing' => $missing, 'message' => ''];
        if (empty($found)) {
            return $out;
        }
        $payload = ValueNewEventTool::payload($found, $edits, $valueUuid, $attribute->typeDefinitions, $attribute->categoryDefinitions);
        $sent = array_merge(array_column($payload['Attribute'], 'uuid'), array_column($payload['Object'], 'uuid'));
        $saved = $eventModel->saveEnrichmentResults($user, $eventModel->fetchSimpleEvent($user, $eventId), $payload);
        foreach ($sent as $uuid) {
            $state = $saved['results'][$uuid]['state'] ?? 'failed';
            $out[isset($out[$state]) ? $state : 'failed']++;
        }
        $out['message'] = $saved['message'] ?? '';
        return $out;
    }

    /**
     * The picked findings, read from the organisation's stored answers
     * through the path the Enrichment tab draws them with.
     *
     * @param array $user
     * @param string $value
     * @param array $picks
     * @return array [fp => finding (+ `type`, the run's), number not found]
     */
    private function resolve(array $user, $value, array $picks)
    {
        $runs = [];
        foreach ($picks as $pick) {
            $runs[$pick['module'] . '|' . $pick['type']] = [$pick['module'], $pick['type']];
        }
        $indexes = [];
        foreach ($runs as $key => list($module, $type)) {
            $run = $this->model('ValueIntelligence')->forEnrichmentRun($user, $value, [
                'module' => $module, 'type' => $type, 'mode' => 'stored', 'all' => true,
            ])['run'];
            $indexes[$key] = ($run['state'] ?? null) === 'ok' ? ValueNewEventTool::index($run, $value) : [];
        }
        $found = [];
        foreach ($picks as $pick) {
            $hit = $indexes[$pick['module'] . '|' . $pick['type']][$pick['fp']] ?? null;
            if ($hit !== null && !isset($found[$pick['fp']])) {
                $found[$pick['fp']] = $hit + ['type' => $pick['type']];
            }
        }
        return [$found, count($picks) - count($found)];
    }

    /**
     * The value's own attribute: the types it can be saved as — those it
     * already has here and those it was enriched as — and each one's
     * categories.
     *
     * @param array $user
     * @param string $value
     * @param array $picks
     * @return array `value`, `types`, `type`
     */
    private function valueBlock(array $user, $value, array $picks)
    {
        $attribute = $this->model('MispAttribute');
        $candidates = array_column($picks, 'type');
        foreach (Value::asTypes($this->model('Value')->typesFor($user, $value)) as $held) {
            $candidates[] = $held['type'];
        }
        $types = [];
        foreach (array_unique($candidates) as $type) {
            if (strpos($type, '|') !== false || !isset($attribute->typeDefinitions[$type])
                || !ValueTypeGuessTool::accepts($type, $value)
            ) {
                continue;
            }
            $types[] = [
                'type' => $type,
                'categories' => ValueNewEventTool::categoriesFor($type, $attribute->typeDefinitions, $attribute->categoryDefinitions),
                'to_ids' => !empty($attribute->typeDefinitions[$type]['to_ids']),
            ];
        }
        if (empty($types)) {
            $types[] = [
                'type' => 'text',
                'categories' => ValueNewEventTool::categoriesFor('text', $attribute->typeDefinitions, $attribute->categoryDefinitions),
                'to_ids' => false,
            ];
        }
        return ['value' => (string)$value, 'types' => $types, 'type' => $types[0]['type']];
    }

    /**
     * @return array Relationship names, `related-to` first
     */
    private function relationships()
    {
        $names = $this->model('ObjectRelationship')->find('column', [
            'fields' => ['ObjectRelationship.name'],
            'order' => ['ObjectRelationship.name'],
        ]);
        $names = array_values(array_diff(array_map('strval', $names), [ValueNewEventTool::DEFAULT_RELATIONSHIP]));
        array_unshift($names, ValueNewEventTool::DEFAULT_RELATIONSHIP);
        return $names;
    }
}
