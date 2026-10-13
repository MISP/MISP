<?php

/**
 * How many engines called a file bad, out of how many looked.
 *
 * The second shape whose set of templates is a per-vendor roster: two
 * multi-engine services ship a report template each and they share no
 * field names beyond the ratio itself.
 *
 * **The ratio is parsed rather than trusted as a number.** Both
 * templates state it as `5/70`, which sorts as a string, compares as
 * nothing, and cannot be read against a threshold until it is two
 * integers. Splitting it here is also what lets the ledger ask *zero
 * of at least forty* — a question the string cannot answer and which
 * is the whole of the benign reading, because `0/3` is three engines
 * having nothing to say rather than a file seventy engines cleared.
 */
class FileVerdictRenderer extends ValueRendererBase
{
    public $id = 'file-verdict';

    public $templates = array(
        'virustotal-report',
        'google-threat-intelligence-report',
    );

    public $compact = 'Values/Renderers/file_verdict_compact';

    public $full = 'Values/Renderers/file_verdict_full';

    public $eventUse = self::EVENT_EACH;

    /**
     * The defaults the reading uses, stated here for the same reason
     * the reputation renderer states its own: a widget drawn with no
     * profile in hand reads the same way the ledger will.
     */
    const THRESHOLDS = array(
        'malicious_ratio' => 5,
        'benign_engines' => 40,
    );

    public function __construct()
    {
        $this->description = __('How many engines detected a file, of'
            . ' the ones that answered.');
    }

    public function matches(array $objects, array $attributes)
    {
        foreach ($objects as $object) {
            if ($this->reportOf($object) !== null) {
                return true;
            }
        }
        return false;
    }

    public function prepare(array $objects, array $attributes)
    {
        $reports = array();
        foreach ($objects as $object) {
            $report = $this->reportOf($object);
            if ($report === null) {
                continue;
            }
            $report['reading'] = self::readingOf(
                $report,
                self::THRESHOLDS
            );
            $reports[] = $report;
        }
        usort($reports, function ($a, $b) {
            return ($b['ran_at'] ?? 0) - ($a['ran_at'] ?? 0);
        });
        return array(
            'reports' => $reports,
            'headline' => empty($reports) ? null : $reports[0],
            'sources' => $this->sources($objects),
        );
    }

    /**
     * Which way one report points, or null for the middle.
     *
     * Three outcomes and the middle one is deliberate: a handful of
     * detections out of seventy is where multi-engine services
     * disagree with each other most and is not evidence of anything on
     * its own.
     *
     * @param array $report A row from `prepare()`
     * @param array $thresholds
     * @return string|null `threat`, `benign`, or null
     */
    public static function readingOf(array $report, array $thresholds)
    {
        $detected = $report['detected'] ?? null;
        $engines = $report['engines'] ?? null;
        if ($detected === null || $engines === null || $engines < 1) {
            return null;
        }
        $min = isset($thresholds['malicious_ratio'])
            ? (int)$thresholds['malicious_ratio']
            : self::THRESHOLDS['malicious_ratio'];
        if ($detected >= $min) {
            return ReputationRenderer::TOWARD_THREAT;
        }
        $floor = isset($thresholds['benign_engines'])
            ? (int)$thresholds['benign_engines']
            : self::THRESHOLDS['benign_engines'];
        if ($detected === 0 && $engines >= $floor) {
            return ReputationRenderer::TOWARD_BENIGN;
        }
        return null;
    }

    /**
     * @param array $object
     * @return array|null
     */
    private function reportOf(array $object)
    {
        $ratio = $this->value($object, 'detection-ratio');
        if ($ratio === null) {
            return null;
        }
        $split = $this->splitRatio($ratio);
        if ($split === null) {
            return null;
        }
        return array(
            'template' => $object['name'] ?? null,
            'ratio' => $ratio,
            'detected' => $split[0],
            'engines' => $split[1],
            'verdict' => $this->value($object, 'verdict'),
            'severity' => $this->value($object, 'severity'),
            'threat_score' => $this->number(
                $this->value($object, 'threat-score')
            ),
            'community_score' => $this->number(
                $this->value($object, 'community-score')
            ),
            'first_submission' => $this->stamp(
                $this->value($object, 'first-submission')
            ),
            'last_submission' => $this->stamp(
                $this->value($object, 'last-submission')
            ),
            'permalink' => $this->value($object, 'permalink'),
            'comment' => $this->value($object, 'comment'),
            'module' => $object['module'] ?? null,
            'ran_at' => $object['ran_at'] ?? null,
        );
    }

    /**
     * `5/70` as two integers, or null where it is something else.
     *
     * @param string $ratio
     * @return array|null `[detected, engines]`
     */
    private function splitRatio($ratio)
    {
        if (!preg_match('#^\s*(\d+)\s*/\s*(\d+)\s*$#', $ratio, $m)) {
            return null;
        }
        return array((int)$m[1], (int)$m[2]);
    }
}
