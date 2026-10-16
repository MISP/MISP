<?php

App::uses('ValueTrustTool', 'Tools/ValueIntelligence');

/**
 * Grading an organisation from the pages it appears on: which profile a
 * grade is read from, which one a write lands in, and what the write does
 * to `reference.org_trust`.
 *
 * A write only ever lands in a profile the reader owns. When the profile
 * in force is anybody else's, the caller forks it first.
 */
class OrgGradeTool
{
    const MODE_OWN = 'own';
    const MODE_FORK = 'fork';
    const MODE_NONE = 'none';

    /**
     * @param array $resolution AnalystProfile::resolutionFor()
     * @return array `mode`, `profile` (id, name, via) or null
     */
    public static function target(array $resolution)
    {
        $profile = $resolution['profile'] ?? null;
        if (!is_array($profile) || !empty($profile['parameters_unparseable'])) {
            return ['mode' => self::MODE_NONE, 'profile' => null];
        }
        $via = $resolution['via'] ?? null;
        return [
            'mode' => $via === 'user' ? self::MODE_OWN : self::MODE_FORK,
            'profile' => [
                'id' => (int)$profile['id'],
                'name' => (string)$profile['name'],
                'via' => (string)$via,
            ],
        ];
    }

    /**
     * Everything a page needs to show and offer grades.
     *
     * @param array $resolution AnalystProfile::resolutionFor()
     * @return array `grades` (uuid => A…G), `scale` (grade => factor),
     *               `target`, `labels`
     */
    public static function reading(array $resolution)
    {
        $labels = [];
        foreach (ValueTrustTool::GRADE_LABELS as $grade => $label) {
            $labels[$grade] = __($label);
        }
        $plan = ValueTrustTool::planFor($resolution['profile'] ?? null);
        return [
            'grades' => $plan['grades'],
            'scale' => $plan['scale'],
            'target' => self::target($resolution),
            'labels' => $labels,
        ];
    }

    /**
     * The reader's grade of one organisation, or null.
     *
     * @param array $grades self::reading()['grades']
     * @param string|null $uuid
     * @return string|null
     */
    public static function gradeOf(array $grades, $uuid)
    {
        $uuid = strtolower(trim((string)$uuid));
        return $uuid === '' ? null : ($grades[$uuid] ?? null);
    }

    /**
     * A posted grade as stored: A…G, or null for "no opinion".
     *
     * @param mixed $grade
     * @return array `ok`, `grade`
     */
    public static function parse($grade)
    {
        if ($grade === null || $grade === '') {
            return ['ok' => false, 'grade' => null];
        }
        $normalised = ValueTrustTool::normaliseGrade($grade);
        if ($normalised === null) {
            return ['ok' => false, 'grade' => null];
        }
        return [
            'ok' => true,
            'grade' => $normalised === ValueTrustTool::UNRATED ? null : $normalised,
        ];
    }

    /**
     * The profile document with one organisation's grade set or removed.
     *
     * Keys are matched case-insensitively and rewritten lower-case, so an
     * entry the editor stored in upper case is replaced, not duplicated.
     *
     * @param array $parameters
     * @param string $uuid
     * @param string|null $grade A…G, null to remove
     * @return array `parameters`, `previous`, `changed`
     */
    public static function apply(array $parameters, $uuid, $grade)
    {
        $uuid = strtolower(trim((string)$uuid));
        $map = $parameters['reference']['org_trust'] ?? [];
        if (!is_array($map)) {
            $map = [];
        }
        $previous = null;
        foreach ($map as $key => $value) {
            if (strtolower(trim((string)$key)) !== $uuid) {
                continue;
            }
            $normalised = ValueTrustTool::normaliseGrade($value);
            if ($normalised !== null && $normalised !== ValueTrustTool::UNRATED) {
                $previous = $normalised;
            }
            unset($map[$key]);
        }
        if ($grade !== null) {
            $map[$uuid] = $grade;
        }
        if (!isset($parameters['reference']) || !is_array($parameters['reference'])) {
            $parameters['reference'] = [];
        }
        $parameters['reference']['org_trust'] = $map;
        return [
            'parameters' => $parameters,
            'previous' => $previous,
            'changed' => $previous !== $grade,
        ];
    }
}
