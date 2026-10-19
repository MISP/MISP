<?php
App::uses('ValueEnrichmentTool', 'Tools/ValueIntelligence');
App::uses('ValueLabelPriority', 'Tools/ValueIntelligence');
App::uses('ModuleCredentials', 'Tools/AnalystProfile');

/**
 * What the enrichment card at the top of the profile index says: for a site
 * admin, what the enabled profiles ask for that this instance cannot do; for
 * anybody else, which of their own profile's modules can run for them.
 *
 * Pure. Settings arrive through a reader callable, the module list as
 * misp-modules returned it, stored answers as rows.
 */
class IndexCardsTool
{
    const SERVICE_ON = 'on';
    const SERVICE_OFF = 'off';
    const SERVICE_UNREACHABLE = 'unreachable';

    const MODULE_READY = 'ready';
    const MODULE_OFF = 'off';
    const MODULE_SETTINGS = 'settings';
    const MODULE_RESTRICTED = 'restricted';
    const MODULE_MISSING = 'missing';
    const MODULE_FAILING = 'failing';
    const MODULE_UNSTABLE = 'unstable';

    /** The order the groups are drawn in: quickest fix first. */
    const GROUP_ORDER = array(
        self::MODULE_OFF,
        self::MODULE_SETTINGS,
        self::MODULE_FAILING,
        self::MODULE_UNSTABLE,
        self::MODULE_MISSING,
        self::MODULE_RESTRICTED,
    );

    /** A module is failing only once it has failed at least this often. */
    const FAILING_MINIMUM = 3;

    /** Timeouts and crashes, as a share of completed queries, that make a
     * module unstable. */
    const UNSTABLE_SHARE = 0.5;

    /** Run states that mean the module answered. */
    const ANSWERED = array('ok', 'silent');

    /** The label tiers whose taxonomy, switched off, changes the page. */
    const TAXONOMY_TIERS = array(
        ValueLabelPriority::PINNED,
        ValueLabelPriority::PREFERRED,
    );

    /**
     * The enrichment modules misp-modules offers, name => declared settings.
     *
     * The same family the profile editor offers: a module declaring an input
     * and a hover or expansion type (none stated reads as expansion).
     *
     * @param mixed $modules What `Module::getModules()` returned
     * @return array|null Null when the service did not answer with a list
     */
    public static function catalogue($modules)
    {
        if (!is_array($modules)) {
            return null;
        }
        $catalogue = array();
        foreach ($modules as $module) {
            if (!is_array($module) || empty($module['name'])
                || empty($module['mispattributes']['input'])
            ) {
                continue;
            }
            $kinds = isset($module['meta']['module-type'])
                && is_array($module['meta']['module-type'])
                ? array_intersect($module['meta']['module-type'],
                    array('hover', 'expansion'))
                : array('expansion');
            if (empty($kinds)) {
                continue;
            }
            $catalogue[(string)$module['name']] =
                isset($module['meta']['config'])
                && is_array($module['meta']['config'])
                    ? array_values($module['meta']['config'])
                    : array();
        }
        return $catalogue;
    }

    /**
     * Whether the modules service is switched on and answering.
     *
     * @param callable $read
     * @param array|null $catalogue
     * @return string
     */
    public static function service(callable $read, $catalogue)
    {
        if (!$read('Plugin.Enrichment_services_enable')) {
            return self::SERVICE_OFF;
        }
        return $catalogue === null
            ? self::SERVICE_UNREACHABLE
            : self::SERVICE_ON;
    }

    /**
     * The modules some profile asks for: ticked or `auto` on some type.
     *
     * `never` is a refusal, so it asks for nothing.
     *
     * @param array $profiles Each with `name` and `parameters`
     * @return array module => `profiles` (names), `types`, `auto`
     */
    public static function askedModules(array $profiles)
    {
        $asked = array();
        foreach ($profiles as $profile) {
            $plan = ValueEnrichmentTool::planFor($profile);
            foreach ($plan['auto_run'] as $type => $states) {
                foreach ($states as $module => $state) {
                    if ($state === ValueEnrichmentTool::STATE_NEVER) {
                        continue;
                    }
                    if (!isset($asked[$module])) {
                        $asked[$module] = array(
                            'profiles' => array(),
                            'types' => array(),
                            'auto' => false,
                        );
                    }
                    $asked[$module]['profiles'][$profile['name']] = true;
                    $asked[$module]['types'][$type] = true;
                    if ($state === ValueEnrichmentTool::STATE_AUTO) {
                        $asked[$module]['auto'] = true;
                    }
                }
            }
        }
        ksort($asked);
        foreach ($asked as $module => $entry) {
            $asked[$module]['profiles'] = array_keys($entry['profiles']);
            $asked[$module]['types'] = array_keys($entry['types']);
        }
        return $asked;
    }

    /**
     * The taxonomies some profile pins or prefers, lowercased.
     *
     * @param array $profiles Each with `name` and `parameters`
     * @return array namespace => `profiles` (names), `tiers`
     */
    public static function askedTaxonomies(array $profiles)
    {
        $asked = array();
        foreach ($profiles as $profile) {
            $plan = ValueLabelPriority::planFor($profile);
            foreach (self::TAXONOMY_TIERS as $tier) {
                $keys = ValueLabelPriority::keys(
                    $plan, ValueLabelPriority::TAXONOMIES, $tier);
                foreach ($keys as $namespace) {
                    $asked[$namespace]['profiles'][$profile['name']] = true;
                    $asked[$namespace]['tiers'][$tier] = true;
                }
            }
        }
        ksort($asked);
        foreach ($asked as $namespace => $entry) {
            $asked[$namespace] = array(
                'profiles' => array_keys($entry['profiles']),
                'tiers' => array_keys($entry['tiers']),
            );
        }
        return $asked;
    }

    /**
     * The modules whose recent answers are all one failure.
     *
     * One message on every answer is a fault somebody can fix; a module that
     * also answered, or failed in several ways, is meeting values with
     * nothing to say.
     *
     * @param array $answers Stored answers, each with `module`, `state` and
     *                       `message`
     * @return array module => `count`, `message`
     */
    public static function failing(array $answers)
    {
        $seen = array();
        foreach ($answers as $answer) {
            if (empty($answer['module']) || !isset($answer['state'])
                || $answer['state'] === ValueEnrichmentTool::RUN_RUNNING
            ) {
                continue;
            }
            $module = (string)$answer['module'];
            if (!isset($seen[$module])) {
                $seen[$module] = array('answered' => false,
                    'messages' => array(), 'count' => 0);
            }
            if (in_array($answer['state'], self::ANSWERED, true)) {
                $seen[$module]['answered'] = true;
                continue;
            }
            $message = isset($answer['message'])
                && trim((string)$answer['message']) !== ''
                ? trim((string)$answer['message'])
                : (string)$answer['state'];
            $seen[$module]['messages'][$message] = true;
            $seen[$module]['count']++;
        }
        $failing = array();
        foreach ($seen as $module => $entry) {
            if ($entry['answered'] || count($entry['messages']) !== 1
                || $entry['count'] < self::FAILING_MINIMUM
            ) {
                continue;
            }
            $failing[$module] = array(
                'count' => $entry['count'],
                'message' => key($entry['messages']),
            );
        }
        return $failing;
    }

    /**
     * Where one module stands on this instance.
     *
     * @param string $name
     * @param array $catalogue From `catalogue()`
     * @param callable $read
     * @param array $failing From `failing()`
     * @param int|null $orgId The reader's organisation; null for the
     *                        instance view, where a restriction is reported
     *                        rather than applied
     * @param array $unstable From `unstable()`
     * @return array `state`, `unset` (required settings left empty),
     *               `enabled`, `restrict` (an organisation id or null)
     */
    public static function moduleState($name, array $catalogue,
        callable $read, array $failing = array(), $orgId = null,
        array $unstable = array()
    ) {
        $prefix = 'Plugin.Enrichment_' . $name . '_';
        $enabled = (bool)$read($prefix . 'enabled');
        $restrict = $read($prefix . 'restrict');
        $restrict = empty($restrict) ? null : (int)$restrict;
        $out = array(
            'state' => self::MODULE_READY,
            'unset' => array(),
            'enabled' => $enabled,
            'restrict' => $restrict,
        );
        if (!array_key_exists($name, $catalogue)) {
            $out['state'] = self::MODULE_MISSING;
            return $out;
        }
        $out['unset'] = ModuleCredentials::unsetFor(
            $name, $catalogue[$name], $read);
        if (!empty($out['unset'])) {
            $out['state'] = self::MODULE_SETTINGS;
        } elseif (!$enabled) {
            $out['state'] = self::MODULE_OFF;
        } elseif ($restrict !== null
            && ($orgId === null || $restrict !== (int)$orgId)
        ) {
            $out['state'] = self::MODULE_RESTRICTED;
        } elseif (isset($failing[$name])) {
            $out['state'] = self::MODULE_FAILING;
        } elseif (isset($unstable[$name])) {
            $out['state'] = self::MODULE_UNSTABLE;
        }
        return $out;
    }

    /**
     * How the modules the profiles ask for have been answering, as
     * misp-modules counted it since it started.
     *
     * @param mixed $statistics What `Module::getStatistics()` returned
     * @param array $asked From `askedModules()`
     * @return array|null Null when the service gave no usable snapshot
     */
    public static function activity($statistics, array $asked)
    {
        if (!is_array($statistics) || !isset($statistics['modules'])
            || !is_array($statistics['modules'])
        ) {
            return null;
        }
        $counts = array('queries', 'completed', 'module_errors', 'timeouts',
            'exceptions');
        $out = array_fill_keys($counts, 0) + array(
            'uptime' => isset($statistics['uptime_seconds'])
                ? (float)$statistics['uptime_seconds'] : null,
            'average' => null,
            'modules' => array(),
            'idle' => array(),
        );
        $total = 0.0;
        foreach (array_keys($asked) as $name) {
            if (!isset($statistics['modules'][$name])
                || !is_array($statistics['modules'][$name])
            ) {
                continue;
            }
            $module = $statistics['modules'][$name];
            $times = isset($module['response_time_seconds'])
                && is_array($module['response_time_seconds'])
                ? $module['response_time_seconds'] : array();
            $row = array('name' => $name);
            foreach ($counts as $count) {
                $row[$count] = isset($module[$count]) ? (int)$module[$count] : 0;
            }
            if ($row['queries'] === 0) {
                $out['idle'][] = $name;
                continue;
            }
            $row['average'] = isset($times['average'])
                ? (float)$times['average'] : null;
            $row['max'] = isset($times['max']) ? (float)$times['max'] : null;
            $row['last_query_at'] = empty($module['last_query_at'])
                ? null : (string)$module['last_query_at'];
            foreach ($counts as $count) {
                $out[$count] += $row[$count];
            }
            $total += isset($times['total']) ? (float)$times['total'] : 0.0;
            $out['modules'][] = $row;
        }
        if ($out['completed'] > 0) {
            $out['average'] = $total / $out['completed'];
        }
        usort($out['modules'], function ($a, $b) {
            return $b['queries'] - $a['queries']
                ?: strcmp($a['name'], $b['name']);
        });
        return $out;
    }

    /**
     * The modules that mostly time out or crash: a fault in the service or
     * in the timeout, where a module error is usually a value with no
     * answer.
     *
     * @param array|null $activity From `activity()`
     * @return array module => `completed`, `timeouts`, `exceptions`
     */
    public static function unstable($activity)
    {
        $unstable = array();
        if (empty($activity['modules'])) {
            return $unstable;
        }
        foreach ($activity['modules'] as $row) {
            $faults = $row['timeouts'] + $row['exceptions'];
            if ($row['completed'] < self::FAILING_MINIMUM
                || $faults < self::UNSTABLE_SHARE * $row['completed']
            ) {
                continue;
            }
            $unstable[$row['name']] = array(
                'completed' => $row['completed'],
                'timeouts' => $row['timeouts'],
                'exceptions' => $row['exceptions'],
            );
        }
        return $unstable;
    }

    /**
     * The site admin's card.
     *
     * @param array $profiles Every enabled profile, with `name` and
     *                        `parameters`
     * @param mixed $modules What `Module::getModules()` returned
     * @param callable $read
     * @param array $answers Recent stored answers, newest first
     * @param array $taxonomies namespace (lowercased) => `id`,
     *                          `namespace`, `enabled`, for the namespaces
     *                          `askedTaxonomies()` named
     * @param mixed $statistics What `Module::getStatistics()` returned
     * @return array
     */
    public static function diagnostic(array $profiles, $modules,
        callable $read, array $answers, array $taxonomies,
        $statistics = null
    ) {
        $catalogue = self::catalogue($modules);
        $asked = self::askedModules($profiles);
        $out = array(
            'service' => self::service($read, $catalogue),
            'gate' => ValueEnrichmentTool::normaliseGate(
                $read('Plugin.ValueIntelligence_enrichment_auto_run')),
            'asked' => count($asked),
            'auto' => count(array_filter(array_column($asked, 'auto'))),
            'ready' => 0,
            'attention' => 0,
            'groups' => array(),
            'activity' => null,
            'taxonomies' => self::__taxonomyGroups(
                self::askedTaxonomies($profiles), $taxonomies),
        );
        $out['attention'] += count($out['taxonomies']['off']);
        if ($out['service'] !== self::SERVICE_ON) {
            return $out;
        }
        $failing = self::failing($answers);
        $out['activity'] = self::activity($statistics, $asked);
        $unstable = self::unstable($out['activity']);
        $groups = array_fill_keys(self::GROUP_ORDER, array());
        foreach ($asked as $name => $entry) {
            $state = self::moduleState($name, $catalogue, $read, $failing,
                null, $unstable);
            if ($state['state'] === self::MODULE_READY) {
                $out['ready']++;
                continue;
            }
            $groups[$state['state']][] = $entry + array(
                'name' => $name,
                'unset' => $state['unset'],
                'enabled' => $state['enabled'],
                'restrict' => $state['restrict'],
                'failing' => isset($failing[$name]) ? $failing[$name] : null,
                'unstable' => isset($unstable[$name])
                    ? $unstable[$name] : null,
            );
            if ($state['state'] !== self::MODULE_RESTRICTED) {
                $out['attention']++;
            }
        }
        $out['groups'] = array_filter($groups);
        return $out;
    }

    /**
     * The card for a reader who is not a site admin: their own profile.
     *
     * @param array|null $profile The profile in force for them
     * @param mixed $modules What `Module::getModules()` returned
     * @param callable $read
     * @param array $user
     * @return array
     */
    public static function reader($profile, $modules, callable $read,
        array $user
    ) {
        $catalogue = self::catalogue($modules);
        $asked = $profile === null
            ? array()
            : self::askedModules(array($profile));
        $out = array(
            'profile' => $profile === null ? null : $profile['name'],
            'service' => self::service($read, $catalogue),
            'can_run' => !empty($user['Role']['perm_add']),
            'asked' => count($asked),
            'ready' => 0,
            'groups' => array(),
            'auto' => array(),
            'auto_held' => null,
        );
        if ($out['service'] !== self::SERVICE_ON) {
            return $out;
        }
        $groups = array_fill_keys(self::GROUP_ORDER, array());
        foreach ($asked as $name => $entry) {
            $state = self::moduleState($name, $catalogue, $read, array(),
                isset($user['org_id']) ? (int)$user['org_id'] : 0);
            if ($state['state'] === self::MODULE_READY) {
                $out['ready']++;
                if ($entry['auto']) {
                    $out['auto'][] = $name;
                }
                continue;
            }
            $groups[$state['state']][] = $name;
        }
        $out['groups'] = array_filter($groups);
        $gate = ValueEnrichmentTool::normaliseGate(
            $read('Plugin.ValueIntelligence_enrichment_auto_run'));
        if (!empty($out['auto']) && !ValueEnrichmentTool::gateAllows(
            $gate, !empty($user['Role']['perm_site_admin']))
        ) {
            $out['auto_held'] = $gate;
        }
        return $out;
    }

    /**
     * @param array $asked From `askedTaxonomies()`
     * @param array $taxonomies namespace (lowercased) => row
     * @return array `off` and `missing`, each a list
     */
    private static function __taxonomyGroups(array $asked, array $taxonomies)
    {
        $groups = array('off' => array(), 'missing' => array());
        foreach ($asked as $namespace => $entry) {
            if (!isset($taxonomies[$namespace])) {
                $groups['missing'][] = $entry + array(
                    'namespace' => $namespace, 'id' => null);
                continue;
            }
            $row = $taxonomies[$namespace];
            if (empty($row['enabled'])) {
                $groups['off'][] = $entry + array(
                    'namespace' => $row['namespace'],
                    'id' => (int)$row['id'],
                );
            }
        }
        return $groups;
    }
}
