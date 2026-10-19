<?php
App::uses('AnalystGraphDocumentTool', 'Tools');
App::uses('CakeText', 'Utility');
App::uses('Validation', 'Utility');

/**
 * A new event made from a value page: the value, plus the enrichment findings
 * the reader picked. Findings are named by the fingerprint analyst graphs give
 * module answers, so a pick survives a reload and a re-run that returns it.
 */
class ValueNewEventTool
{
    const KINDS = ['attributes' => 'attribute', 'objects' => 'object', 'elements' => 'element'];

    const MAX_PICKS = 500;

    const DEFAULT_RELATIONSHIP = 'related-to';

    /**
     * @param array $item An attribute, object or element of a shaped run
     * @param string $kind attribute|object|element
     * @param string $module
     * @return string
     */
    public static function fingerprint(array $item, $kind, $module)
    {
        if ($kind === 'object') {
            $content = [
                'kind' => 'object',
                'name' => (string)($item['name'] ?? ''),
                'attributes' => array_map(function ($attribute) {
                    return [
                        'relation' => (string)($attribute['relation'] ?? ''),
                        'type' => (string)($attribute['type'] ?? ''),
                        'value' => (string)($attribute['value'] ?? ''),
                    ];
                }, $item['attributes'] ?? []),
            ];
        } elseif ($kind === 'element') {
            $content = ['kind' => 'element', 'types' => array_values((array)($item['types'] ?? [''])), 'value' => (string)($item['value'] ?? '')];
        } else {
            $content = ['kind' => 'attribute', 'type' => (string)($item['type'] ?? ''), 'value' => (string)($item['value'] ?? '')];
        }
        return AnalystGraphDocumentTool::answerUuid($content, (string)$module);
    }

    /**
     * Modules echo the value they were asked about back as an attribute.
     *
     * @param array $item
     * @param string $kind
     * @param string $value
     * @return bool
     */
    public static function isValueItself(array $item, $kind, $value)
    {
        return $kind !== 'object' && (string)($item['value'] ?? '') === (string)$value;
    }

    /**
     * The picks a request names: `{fp, module, type}` each, the run they were
     * drawn from being `module` asked as `type`.
     *
     * @param mixed $raw A JSON string or a decoded list
     * @return array
     */
    public static function picks($raw)
    {
        if (is_string($raw)) {
            $raw = json_decode($raw, true);
        }
        if (!is_array($raw)) {
            return [];
        }
        $out = [];
        foreach ($raw as $pick) {
            if (!is_array($pick) || !Validation::uuid($pick['fp'] ?? '')
                || !is_string($pick['module'] ?? null) || !preg_match(AnalystGraphDocumentTool::MODULE_PATTERN, $pick['module'])
                || !is_string($pick['type'] ?? null) || $pick['type'] === ''
            ) {
                continue;
            }
            $fp = strtolower($pick['fp']);
            if (!isset($out[$fp])) {
                $out[$fp] = ['fp' => $fp, 'module' => $pick['module'], 'type' => $pick['type']];
            }
            if (count($out) >= self::MAX_PICKS) {
                break;
            }
        }
        return array_values($out);
    }

    /**
     * Every finding of one run by fingerprint, the value itself left out.
     *
     * @param array $run A shaped run, as forEnrichmentRun returns it
     * @param string $value
     * @return array fp => ['kind', 'module', 'item']
     */
    public static function index(array $run, $value)
    {
        $out = [];
        foreach (self::KINDS as $list => $kind) {
            foreach ($run[$list] ?? [] as $item) {
                if (!is_array($item) || self::isValueItself($item, $kind, $value)) {
                    continue;
                }
                $fp = self::fingerprint($item, $kind, $run['module']);
                if (!isset($out[$fp])) {
                    $out[$fp] = ['kind' => $kind, 'module' => $run['module'], 'item' => $item];
                }
            }
        }
        return $out;
    }

    /**
     * The categories a type may be saved under, its default first.
     *
     * @param string $type
     * @param array $typeDefinitions
     * @param array $categoryDefinitions
     * @return array
     */
    public static function categoriesFor($type, array $typeDefinitions, array $categoryDefinitions)
    {
        $out = [];
        $default = $typeDefinitions[$type]['default_category'] ?? null;
        if ($default !== null) {
            $out[] = $default;
        }
        foreach ($categoryDefinitions as $category => $definition) {
            if (in_array($type, $definition['types'] ?? [], true) && $category !== $default) {
                $out[] = $category;
            }
        }
        return $out;
    }

    /**
     * What saveEnrichmentResults() takes, for the findings as the reader left
     * them in the dialog. Every result names the value's attribute as its
     * origin, and every object references it.
     *
     * @param array $findings fp => resolved finding (see index())
     * @param array $edits fp => `category`, `to_ids`, `type`, `relationship`
     * @param string $valueUuid
     * @param array $typeDefinitions
     * @param array $categoryDefinitions
     * @return array
     */
    public static function payload(array $findings, array $edits, $valueUuid,
        array $typeDefinitions, array $categoryDefinitions
    ) {
        $data = ['Attribute' => [], 'Object' => []];
        foreach ($findings as $fp => $finding) {
            $edit = $edits[$fp] ?? [];
            $item = $finding['item'];
            if ($finding['kind'] === 'object') {
                $relationship = trim((string)($edit['relationship'] ?? ''));
                $object = [
                    'uuid' => CakeText::uuid(),
                    'name' => (string)$item['name'],
                    'comment' => (string)($item['comment'] ?? ''),
                    'origins' => [$valueUuid],
                    'Attribute' => [],
                    'ObjectReference' => [[
                        'referenced_uuid' => $valueUuid,
                        'relationship_type' => $relationship === '' ? self::DEFAULT_RELATIONSHIP : mb_substr($relationship, 0, 191),
                    ]],
                ];
                foreach ($item['attributes'] ?? [] as $attribute) {
                    $object['Attribute'][] = [
                        'uuid' => CakeText::uuid(),
                        'object_relation' => (string)$attribute['relation'],
                        'type' => (string)$attribute['type'],
                        'category' => (string)($attribute['category'] ?? ''),
                        'value' => (string)$attribute['value'],
                        'to_ids' => !empty($attribute['to_ids']),
                        'comment' => (string)($attribute['comment'] ?? ''),
                    ];
                }
                $data['Object'][] = $object;
                continue;
            }
            $types = $finding['kind'] === 'element'
                ? array_values((array)$item['types'])
                : [(string)$item['type']];
            $type = in_array($edit['type'] ?? null, $types, true) ? $edit['type'] : $types[0];
            $categories = self::categoriesFor($type, $typeDefinitions, $categoryDefinitions);
            $category = in_array($edit['category'] ?? null, $categories, true)
                ? $edit['category']
                : ($finding['kind'] === 'attribute' && in_array($item['category'] ?? null, $categories, true)
                    ? $item['category']
                    : ($categories[0] ?? null));
            $data['Attribute'][] = [
                'uuid' => CakeText::uuid(),
                'type' => $type,
                'category' => $category,
                'value' => (string)$item['value'],
                'to_ids' => array_key_exists('to_ids', $edit)
                    ? !empty($edit['to_ids'])
                    : ($finding['kind'] === 'attribute' ? !empty($item['to_ids']) : !empty($typeDefinitions[$type]['to_ids'])),
                'comment' => (string)($item['comment'] ?? ''),
                'origins' => [$valueUuid],
            ];
        }
        return $data;
    }
}
