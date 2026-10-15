<?php

App::uses('ValueRendererTool', 'Tools/ValueIntelligence');

/**
 * How old the domain was when MISP first saw the value.
 *
 * Attackers register a domain and use it within days; a domain
 * registered six days before anybody reported it is a burner, and stays
 * one after it turns three. So the age is measured **at the first
 * report**, never today, from a stored registration answer — the
 * registry's creation date, which `rdap` returns in a `whois` object.
 * `RegistrationRenderer::readingOf()` does the reading, so the widget and
 * this row cannot disagree about one answer.
 *
 * ## Two tiers, and older is silent
 *
 * *Fresh* is a strong, specific tell. *Young* is weak: domains are often
 * held for weeks or months before use, but compromised legitimate sites
 * are sometimes young too. An old domain says nothing either way —
 * aged and compromised domains are both common — so it draws no row.
 *
 * **The young row never contests a reading on its own.** The dispute
 * check counts sign, not size, so a weak row would otherwise contest a
 * reading something calls harmless exactly as hard as a fresh one does.
 * It is marked so the check leaves it out; it still supports a threat
 * reading.
 *
 * ## One row, from the newest graded answer
 *
 * Several modules relaying one registry record are one fact told
 * several times, so this draws one row and names the modules that
 * agree. Only graded modules count, as for `enrichment.answer`; an
 * ungraded answer that would have scored is set aside with the reason.
 * A creation date after the first report belongs to a later registration
 * than the one reported, and is set aside too.
 */
class EnrichmentRegistrationAge extends ValueSignalBase
{
    public $id = 'enrichment.registration_age';

    public $group = 'Enrichment';

    public $evidence_class = self::EVIDENCE_AGGREGATE;

    // An age reads the value: it says what kind of domain this is.
    public $axis = self::AXIS_LEAN;

    public $reads = array('enrichment', 'occurrences');

    public $tab = 'enrichment';

    public function __construct()
    {
        $this->description = __(
            'Adds points when the domain was registered shortly before it'
            . ' was first reported. Only modules you have graded count.'
        );
        $this->help = array(
            'name' => __('Registration age'),
            'what' => __(
                'Compares when the domain was registered, from a stored'
                . ' registration answer such as RDAP\'s, with when MISP first'
                . ' saw the value. Attackers use new domains within days, so'
                . ' a domain registered just before its first report points'
                . ' at a threat. A subdomain is read against the domain it'
                . ' sits under. An older domain adds nothing: compromised'
                . ' sites and long-held domains are common.'
            ),
            'how' => __(
                'Registered at most {fresh_days} days before the first'
                . ' report: {fresh} points. At most {young_days} days:'
                . ' {young} points. Both are multiplied by the module\'s'
                . ' grade. Older: no row.'
            ),
            'note' => __(
                'The young row supports a threat reading but never makes a'
                . ' reading contested on its own; the fresh row can. A'
                . ' domain registered again after its first report is not'
                . ' counted, because the record describes a later'
                . ' registration. Grade modules under Sources & reputation'
                . ' → Enrichment module reputation.'
            ),
            'settings' => array(
                'fresh' => __(
                    'Points for a domain registered just before its first'
                    . ' report.'
                ),
                'young' => __(
                    'Points for a domain a few months old at its first'
                    . ' report. Keep it small: compromised legitimate sites'
                    . ' are sometimes this young.'
                ),
                'fresh_days' => __(
                    'The most days between registration and first report'
                    . ' that still reads as fresh.'
                ),
                'young_days' => __(
                    'The most days that still reads as young.'
                ),
            ),
            'recipes' => array(
                array(
                    'want' => __('Only very new domains should count'),
                    'do' => __('Lower fresh_days to 7 and set young to 0.'),
                ),
                array(
                    'want' => __('Domains held for a few months before use'
                        . ' should count more'),
                    'do' => __('Raise young to 8.'),
                ),
                array(
                    'want' => __('A registration answer should count at'
                        . ' all'),
                    'do' => __('Grade the module that gave it, e.g. rdap,'
                        . ' under Sources & reputation.'),
                ),
            ),
        );
        $this->points_schema = array(
            'fresh' => array(
                'type' => 'int',
                'default' => 12,
                'label' => __('Points when registered just before the'
                    . ' first report'),
            ),
            'young' => array(
                'type' => 'int',
                'default' => 4,
                'label' => __('Points when a few months old at the first'
                    . ' report'),
            ),
        );
        // RegistrationRenderer::THRESHOLDS; renderers load after signals.
        $this->config_schema = array(
            'fresh_days' => array(
                'type' => 'int',
                'default' => 30,
                'label' => __('Fresh up to (days)'),
            ),
            'young_days' => array(
                'type' => 'int',
                'default' => 180,
                'label' => __('Young up to (days)'),
            ),
        );
    }

    public function evaluate(array $context, array $config)
    {
        $runs = isset($context['enrichment']['runs'])
            && is_array($context['enrichment']['runs'])
            ? $context['enrichment']['runs']
            : array();
        $firstReport = $context['occurrences']['oldest'] ?? null;
        $value = (string)($context['value'] ?? '');
        if (empty($runs) || empty($firstReport) || $value === '') {
            return null;
        }
        $drawn = ValueRendererTool::drawFor($runs);
        if (empty($drawn['registration']['data']['records'])) {
            return null;
        }
        $thresholds = array(
            'fresh_days' => $this->setting($config, 'fresh_days'),
            'young_days' => $this->setting($config, 'young_days'),
        );
        $factors = $context['enrichment']['trust']['factors'] ?? array();
        $grades = $context['enrichment']['trust']['grades'] ?? array();

        $graded = array();
        $ungraded = array();
        foreach ($drawn['registration']['data']['records'] as $record) {
            $reading = RegistrationRenderer::readingOf(
                $record,
                $value,
                $firstReport,
                $thresholds
            );
            if ($reading === null) {
                continue;
            }
            $module = (string)($record['module'] ?? '');
            $reading += array(
                'module' => $module,
                'ran_at' => (int)($record['ran_at'] ?? 0),
                'factor' => (float)($factors[$module] ?? 0.0),
                'grade' => $grades[$module] ?? null,
            );
            if ($reading['factor'] > 0.0) {
                $graded[] = $reading;
            } else {
                $ungraded[] = $reading;
            }
        }

        if (empty($graded)) {
            foreach ($ungraded as $reading) {
                if ($reading['tier'] !== null) {
                    return array('rows' => array(), 'not_counted' => array(
                        $this->aside($reading, 'policy', 'ungraded', __(
                            'Your profile has not graded this module, so'
                            . ' its answer is shown and not counted. Grade'
                            . ' it under Sources & reputation to have it'
                            . ' count.'
                        )),
                    ));
                }
            }
            return null;
        }

        // Records arrive newest first, so the first graded one is chosen.
        $chosen = $graded[0];
        if ($chosen['reregistered']) {
            return array('rows' => array(), 'not_counted' => array(
                $this->aside($chosen, 'nodata', 'reregistered', sprintf(
                    __('Registered on %1$s, after MISP first saw it on'
                        . ' %2$s, so this record describes a later'
                        . ' registration than the one reported.'),
                    date('Y-m-d', $chosen['created']),
                    date('Y-m-d', $chosen['first_report'])
                )),
            ));
        }
        if ($chosen['tier'] === null) {
            return null;
        }

        $young = $chosen['tier'] === RegistrationRenderer::YOUNG;
        $row = $this->row(
            $this->points($config, $young ? 'young' : 'fresh')
                * $chosen['factor'],
            $this->sentence($chosen),
            $this->evidence($chosen, $graded, $context),
            $context,
            $this->stampAsOf($chosen['ran_at'], $context)
        );
        if ($young) {
            // Left out of the dispute check: it supports, never contests.
            $row['voice'] = true;
        }
        return $row;
    }

    /**
     * @param array $reading
     * @return string
     */
    private function sentence(array $reading)
    {
        $age = $this->duration($reading['age_days']);
        if ($reading['match'] === 'parent') {
            return sprintf(
                __('%1$s was registered %2$s before this was first'
                    . ' reported'),
                $reading['domain'],
                $age
            );
        }
        return $reading['age_days'] === 0
            ? __('Registered the day it was first reported')
            : sprintf(
                __('Registered %s before it was first reported'),
                $age
            );
    }

    /**
     * The module, the date and the grade, then whoever agrees and
     * whoever does not.
     *
     * @param array $chosen
     * @param array $graded Every graded reading, chosen first
     * @param array $context
     * @return string
     */
    private function evidence(array $chosen, array $graded, array $context)
    {
        $now = isset($context['now']) ? (int)$context['now'] : time();
        $parts = array(sprintf(
            __('%1$s · created %2$s · asked %3$s · graded %4$s'),
            $chosen['module'],
            date('Y-m-d', $chosen['created']),
            $this->agoPhrase(
                (int)floor(max(0, $now - $chosen['ran_at']) / 86400)
            ),
            $chosen['grade'] === null ? '?' : $chosen['grade']
        ));
        $tolerance = RegistrationRenderer::REREGISTRATION_TOLERANCE_DAYS
            * 86400;
        $agree = array();
        $disagree = array();
        foreach (array_slice($graded, 1) as $other) {
            if ($other['module'] === $chosen['module']) {
                continue;
            }
            if (abs($other['created'] - $chosen['created']) <= $tolerance) {
                $agree[] = $other['module'];
            } else {
                $disagree[] = sprintf(
                    __('%1$s says %2$s'),
                    $other['module'],
                    date('Y-m-d', $other['created'])
                );
            }
        }
        if (!empty($agree)) {
            $parts[] = sprintf(
                __('%s agree'),
                implode(', ', array_merge(
                    array($chosen['module']),
                    array_unique($agree)
                ))
            );
        }
        return implode('; ', array_merge($parts, $disagree));
    }

    /**
     * An age as a length of time, in the units `agoPhrase()` uses.
     *
     * @param int $days
     * @return string
     */
    private function duration($days)
    {
        $days = (int)$days;
        if ($days === 1) {
            return __('1 day');
        }
        if ($days < 60) {
            return sprintf(__('%d days'), $days);
        }
        $months = (int)round($days / 30);
        if ($months < 24) {
            return sprintf(__('%d months'), $months);
        }
        return sprintf(__('%d years'), (int)round($days / 365));
    }

    /**
     * A row that stays on the page and out of the sum.
     *
     * @param array $reading
     * @param string $reason
     * @param string $kind
     * @param string $why
     * @return array
     */
    private function aside(array $reading, $reason, $kind, $why)
    {
        return array(
            'title' => sprintf(
                __('%1$s · registered %2$s'),
                $reading['module'],
                date('Y-m-d', $reading['created'])
            ),
            'note' => $why,
            'reason' => $reason,
            'kind' => $kind,
            'source' => 'enrichment',
            'id' => $this->id,
        );
    }
}
