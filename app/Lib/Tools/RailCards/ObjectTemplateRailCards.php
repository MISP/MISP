<?php
App::uses('LazyRailCards', 'Tools/RailCards');

/**
 * Rail cards for an object template. $template is ['ObjectTemplate' => [...]]
 * as ObjectTemplatesController::view loads it.
 */
class ObjectTemplateRailCards extends LazyRailCards
{
    const TYPE_LIMIT = 8;

    protected function railCardUrl()
    {
        return '/object_templates/railCard/';
    }

    protected function lazyCards()
    {
        return [
            'template-usage' => ['usage', __('Usage'), 'fas fa-chart-simple', 'usage'],
        ];
    }

    /**
     * Objects the user can see that were built from any version of the
     * template, split by whether they follow the installed version.
     *
     * @param array $user
     * @param array $template
     * @return array
     */
    public function usage(array $user, array $template)
    {
        $Object = ClassRegistry::init('MispObject');
        $conditions = [
            'Object.template_uuid' => $template['ObjectTemplate']['uuid'],
            'Object.deleted' => 0,
        ];
        $acl = $Object->buildConditions($user);
        if (!empty($acl)) {
            $conditions['AND'][] = $acl;
        }
        $query = [
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => empty($acl) ? [] : ['Event'],
        ];
        $byVersion = $Object->find('all', $query + [
            'fields' => ['Object.template_version', 'COUNT(Object.id) AS object_count'],
            'group' => ['Object.template_version'],
        ]);
        $totals = $Object->find('first', $query + [
            'fields' => ['COUNT(DISTINCT Object.event_id) AS event_count', 'MAX(Object.timestamp) AS last_ts'],
        ]);

        $installed = (int)$template['ObjectTemplate']['version'];
        $current = $older = $newer = 0;
        foreach ($byVersion as $row) {
            $version = (int)$row['Object']['template_version'];
            $count = (int)$row[0]['object_count'];
            if ($version === $installed) {
                $current += $count;
            } else if ($version < $installed) {
                $older += $count;
            } else {
                $newer += $count;
            }
        }
        $total = $current + $older + $newer;
        $events = (int)($totals[0]['event_count'] ?? 0);
        $split = [
            ['label' => __('Installed version (v%s)', $installed), 'count' => $current, 'tone' => 'ok'],
            ['label' => __('Older versions'), 'count' => $older, 'tone' => $older ? 'warn' : null],
        ];
        if ($newer) {
            $split[] = ['label' => __('Newer than installed'), 'count' => $newer, 'tone' => 'info'];
        }
        list(, $title, $icon) = $this->head('template-usage');
        return RailCard::usage(
            'template-usage',
            $title,
            $icon,
            [
                'count' => $total,
                'label' => __n('object', 'objects', $total),
                'context' => $total ? __n('in %s event', 'in %s events', $events, $events) : null,
            ],
            $total ? $split : [],
            RailCard::last($totals[0]['last_ts'] ?? null, __('Last used')),
            ['empty' => __('No object uses this template yet.'), 'lazy' => true]
        );
    }

    /**
     * @param array $template
     * @return array
     */
    public function inventory(array $template)
    {
        $elements = ClassRegistry::init('ObjectTemplateElement')->find('all', [
            'recursive' => -1,
            'conditions' => ['ObjectTemplateElement.object_template_id' => $template['ObjectTemplate']['id']],
            'fields' => ['object_relation', 'type', 'multiple', 'disable_correlation'],
        ]);
        $requirements = $template['ObjectTemplate']['requirements'] ?? [];
        $required = array_flip((array)($requirements['required'] ?? []));
        $oneOf = array_flip((array)($requirements['requiredOneOf'] ?? []));

        $types = [];
        $need = ['required' => 0, 'oneof' => 0, 'optional' => 0];
        $multiple = $noCorrelation = $flagged = 0;
        foreach ($elements as $element) {
            $e = $element['ObjectTemplateElement'];
            $types[$e['type']] = ($types[$e['type']] ?? 0) + 1;
            if (isset($required[$e['object_relation']])) {
                $need['required']++;
            } else if (isset($oneOf[$e['object_relation']])) {
                $need['oneof']++;
            } else {
                $need['optional']++;
            }
            $multiple += $e['multiple'] ? 1 : 0;
            $noCorrelation += $e['disable_correlation'] ? 1 : 0;
            $flagged += $e['multiple'] || $e['disable_correlation'] ? 1 : 0;
        }
        arsort($types);
        $typeFacets = [];
        foreach (array_slice($types, 0, self::TYPE_LIMIT, true) as $type => $count) {
            $typeFacets[] = ['label' => (string)$type, 'count' => $count, 'filter' => ['type' => (string)$type]];
        }
        $needLabels = [
            'required' => __('Required'),
            'oneof' => __('At least one of'),
            'optional' => __('Optional'),
        ];
        $needFacets = [];
        foreach ($need as $key => $count) {
            if ($count) {
                $needFacets[] = ['label' => $needLabels[$key], 'count' => $count, 'filter' => ['requirement' => $key]];
            }
        }
        $flagFacets = [];
        if ($multiple) {
            $flagFacets[] = ['label' => __('Repeatable'), 'count' => $multiple, 'filter' => ['multiple' => true]];
        }
        if ($noCorrelation) {
            $flagFacets[] = ['label' => __('No correlation'), 'count' => $noCorrelation, 'filter' => ['disable_correlation' => true]];
        }
        $total = count($elements);
        $groups = [
            [
                'key' => 'requirement', 'label' => __('Requirement'), 'icon' => 'fas fa-list-check',
                'count' => $total, 'partition' => true, 'facets' => $needFacets,
            ],
            [
                'key' => 'type',
                'label' => __n('%s attribute type', '%s attribute types', count($types), count($types)),
                'icon' => 'misp-icon misp-icon-attribute misp-simple', 'color' => 'type',
                'count' => $total, 'partition' => true, 'facets' => $typeFacets,
                'more' => max(0, count($types) - self::TYPE_LIMIT),
            ],
        ];
        if (!empty($flagFacets)) {
            $groups[] = [
                'key' => 'flags', 'label' => __('Flagged'), 'icon' => 'fas fa-flag',
                'count' => $flagged, 'facets' => $flagFacets,
            ];
        }
        return RailCard::inventory(
            'template-inventory',
            __('Inventory'),
            'fas fa-boxes-stacked',
            ['count' => $total, 'label' => __n('attribute', 'attributes', $total)],
            $total ? $groups : [],
            false,
            [
                'link' => ['label' => __('Elements'), 'href' => '#tab-elements'],
                'empty' => __('This template defines no attributes.'),
            ]
        );
    }

    /**
     * Every version of the template kept on the instance, newest first.
     *
     * @param array $template
     * @return array
     */
    public function versions(array $template)
    {
        $versions = ClassRegistry::init('ObjectTemplate')->find('all', [
            'recursive' => -1,
            'conditions' => ['ObjectTemplate.uuid' => $template['ObjectTemplate']['uuid']],
            'fields' => ['id', 'version', 'active'],
            'order' => ['ObjectTemplate.version' => 'DESC'],
        ]);
        $rows = [];
        foreach ($versions as $version) {
            $v = $version['ObjectTemplate'];
            $isThis = (int)$v['id'] === (int)$template['ObjectTemplate']['id'];
            $rows[] = [
                'label' => __('Version %s', $v['version']),
                'href' => $isThis ? null : '/objectTemplates/view/' . $v['id'],
                'icon' => 'fas fa-code-branch',
                'badge' => $v['active'] ? ['label' => __('Active'), 'tone' => 'ok'] : null,
                'tone' => $isThis ? 'info' : null,
            ];
        }
        return RailCard::rows('template-versions', __('Versions'), 'fas fa-code-branch', $rows, null, [
            'empty' => __('Only this version is installed.'),
        ]);
    }

    /**
     * Event templates the user can see that need this template.
     *
     * @param array $user
     * @param array $template
     * @return array
     */
    public function requiredBy(array $user, array $template)
    {
        $Dependency = ClassRegistry::init('EventTemplateObjectDependency');
        $conditions = ['EventTemplateObjectDependency.object_template_uuid' => $template['ObjectTemplate']['uuid']];
        if (empty($user['Role']['perm_site_admin'])) {
            $conditions['OR'] = [
                'EventTemplate.org_id' => (int)$user['org_id'],
                'EventTemplate.distribution' => 1,
            ];
        }
        $dependencies = $Dependency->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['EventTemplateObjectDependency.minimum_version', 'EventTemplate.id', 'EventTemplate.name'],
            'joins' => [[
                'table' => 'event_templates',
                'alias' => 'EventTemplate',
                'type' => 'INNER',
                'conditions' => ['EventTemplate.id = EventTemplateObjectDependency.event_template_id'],
            ]],
            'order' => ['EventTemplate.name' => 'ASC'],
        ]);
        $installed = (int)$template['ObjectTemplate']['version'];
        $rows = [];
        foreach ($dependencies as $dependency) {
            $minimum = (int)$dependency['EventTemplateObjectDependency']['minimum_version'];
            $tooOld = $minimum > $installed;
            $rows[] = [
                'label' => $dependency['EventTemplate']['name'],
                'href' => '/event_templates/view/' . $dependency['EventTemplate']['id'],
                'icon' => 'fas fa-layer-group',
                'meta' => [__('needs v%s or later', $minimum)],
                'tone' => $tooOld ? 'warn' : null,
                'badge' => $tooOld ? ['label' => __('Update needed'), 'tone' => 'warn'] : null,
            ];
        }
        return RailCard::rows('template-required-by', __('Required by'), 'fas fa-layer-group', $rows, null, [
            'empty' => __('No event template depends on it.'),
        ]);
    }
}
