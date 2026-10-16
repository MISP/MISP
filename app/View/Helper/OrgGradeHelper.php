<?php
App::uses('AppHelper', 'View/Helper');
App::uses('EventCardTool', 'Tools/EventOverview');
App::uses('OrgGradeTool', 'Tools/AnalystProfile');

/**
 * The reader's grade of an organisation, as a badge on the organisation's
 * mark that opens the grade menu (org-grade.js).
 */
class OrgGradeHelper extends AppHelper
{
    public $helpers = ['OrgImg'];

    /**
     * @param array|null $grading OrgGradeTool::reading()
     * @return bool
     */
    public function enabled($grading)
    {
        return is_array($grading)
            && ($grading['target']['mode'] ?? OrgGradeTool::MODE_NONE) !== OrgGradeTool::MODE_NONE;
    }

    /**
     * What org-grade.js needs, once per page, plus its assets.
     *
     * @param array|null $grading
     * @return string
     */
    public function config($grading)
    {
        if (!$this->enabled($grading)) {
            return '';
        }
        $config = [
            'url' => $this->_View->viewVars['baseurl'] . '/analystProfiles/grade/',
            'target' => $grading['target'],
            'labels' => $grading['labels'],
            'scale' => $grading['scale'],
        ];
        return $this->_View->element('genericElements/assetLoader', [
            'css' => ['org-grade'],
            'js' => ['org-grade'],
        ]) . '<script type="application/json" id="og-config">'
            . json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE)
            . '</script>';
    }

    /**
     * The badge alone, for a mark the caller already draws.
     *
     * @param array $org id, uuid, name
     * @param array|null $grading
     * @param string|null $variant `large` on the event band's logo tile,
     *                             `square` standing alone beside the name
     * @return string
     */
    public function badge(array $org, $grading, $variant = null)
    {
        if (!$this->enabled($grading) || empty($org['uuid'])) {
            return '';
        }
        $uuid = strtolower($org['uuid']);
        $grade = OrgGradeTool::gradeOf($grading['grades'], $uuid);
        $name = (string)($org['name'] ?? '');
        if ($grade === null) {
            $label = __('Grade %s', $name);
        } else {
            $words = $grade . ', ' . ($grading['labels'][$grade] ?? '');
            $label = $grading['target']['mode'] === OrgGradeTool::MODE_OWN
                ? __('Graded %s. Change the grade', $words)
                : __('Graded %s (from %s). Change the grade', $words, $grading['target']['profile']['name']);
        }
        return sprintf(
            '<button type="button" class="og-badge%s%s" data-grade-open="%s" data-grade-for="%s" data-grade="%s"'
            . ' data-org-id="%d" data-org-name="%s" aria-haspopup="menu" aria-expanded="false" title="%s" aria-label="%s">%s</button>',
            $variant ? ' is-' . h($variant) : '',
            $grade === null ? ' is-empty' : ' og-tone-' . $this->tone($grade, $grading['scale']),
            h($uuid),
            h($uuid),
            h($grade ?? ''),
            (int)($org['id'] ?? 0),
            h($name),
            h($label),
            h($name . ': ' . $label),
            $grade === null ? '<i class="fas fa-plus" aria-hidden="true"></i>' : h($grade)
        );
    }

    /**
     * The organisation's logo, or a monogram when it has none, carrying the
     * badge. Without a profile in force, the logo alone as before.
     *
     * @param array $org
     * @param array|null $grading
     * @param int $size
     * @return string
     */
    public function mark(array $org, $grading, $size = 24)
    {
        $logo = $this->OrgImg->getOrgLogoV2($org, $size);
        $badge = $this->badge($org, $grading);
        if ($badge === '') {
            return $logo;
        }
        if ($logo === '') {
            $mono = EventCardTool::monogram($org);
            $logo = sprintf('<span class="og-monogram" aria-hidden="true">%s</span>', h($mono['letters']));
        }
        return '<span class="og-mark">' . $logo . $badge . '</span>';
    }

    /**
     * @param string $grade
     * @param array $scale
     * @return string more, neutral, less or void
     */
    public function tone($grade, array $scale)
    {
        $factor = $scale[$grade] ?? 1.0;
        if ($factor > 1) {
            return 'more';
        }
        if ($factor == 1) {
            return 'neutral';
        }
        return $factor > 0 ? 'less' : 'void';
    }
}
