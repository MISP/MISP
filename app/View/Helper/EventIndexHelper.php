<?php
App::uses('AppHelper', 'View/Helper');
App::uses('EventCardTool', 'Tools/EventOverview');

/**
 * The pieces the Overmind events index draws in both its card and its table
 * views, from the EventCard each event carries
 * (EventsController::__attachCardsToEvents()).
 */
class EventIndexHelper extends AppHelper
{
    public $helpers = ['FontAwesome', 'TagChip', 'OrgImg', 'OrgGrade'];

    const LANES = [
        'attribution' => ['Attribution', 'fas fa-user-secret'],
        'behaviour' => ['Behaviour', 'misp-icon misp-icon-galaxy misp-simple'],
        'classification' => ['Classification', 'misp-icon misp-icon-taxonomy misp-simple'],
    ];

    public function laneLabel($lane)
    {
        return __(self::LANES[$lane][0]);
    }

    public function laneIcon($lane)
    {
        return '<i class="' . self::LANES[$lane][1] . '" aria-hidden="true"></i>';
    }

    public function utc($timestamp)
    {
        return gmdate('Y-m-d H:i', (int)$timestamp) . ' UTC';
    }

    public function plural($n, $one, $many)
    {
        return __n($one, $many, $n, $n);
    }

    /**
     * @param array $event Event row
     * @param string $state EventCard state
     * @return string the state as a sentence, with its publish date
     */
    public function stateTitle(array $event, $state)
    {
        $published = (int)($event['publish_timestamp'] ?? 0);
        if ($state === 'pending') {
            return __('Changes pending: published %s, changed since', $this->utc($published));
        }
        if ($state === 'published') {
            return $published ? __('Published %s', $this->utc($published)) : __('Published');
        }
        return __('Unpublished');
    }

    /**
     * The org's logo, or its monogram.
     */
    public function orgTile(array $org, $size = 22)
    {
        $logo = empty($org) ? '' : $this->OrgImg->getOrgLogoV2($org, $size, false);
        if ($logo !== '') {
            return '<span class="dk-logo">' . $logo . '</span>';
        }
        $mono = EventCardTool::monogram($org);
        return sprintf('<span class="dk-logo is-mono m%d" aria-hidden="true">%s</span>', $mono['index'], h($mono['letters']));
    }

    public function orgTitle(array $row)
    {
        $org = $row['Org'] ?? [];
        $orgc = $row['Orgc'] ?? [];
        $synced = !empty($org['id']) && !empty($orgc['id']) && (int)$org['id'] !== (int)$orgc['id'];
        return __('Created by %s', $orgc['name'] ?? '') . ($synced ? ' · ' . __('held here by %s', $org['name'] ?? '') : '');
    }

    /**
     * The reader's own grade of the creator org: a filled square, nothing
     * when ungraded. With a profile to write to, the square opens the grade
     * menu instead.
     *
     * @param string|null $grade
     * @param array $org
     * @param array|null $grading OrgGradeTool::reading()
     */
    public function grade($grade, array $org, $grading = null)
    {
        if ($this->OrgGrade->enabled($grading)) {
            return $this->OrgGrade->badge($org, $grading, 'square');
        }
        if ($grade === null) {
            return '';
        }
        $title = __('Your grade for %s: %s (analyst profile)', $org['name'] ?? '', $grade);
        return sprintf(
            '<span class="dk-grade is-mine" role="img" title="%s" aria-label="%s">%s</span>',
            h($title),
            h($title),
            h($grade)
        );
    }

    /**
     * The marking slots: the profile's markings, present or absent, then its
     * other pinned taxonomies — admiralty as the org's claim, an outlined
     * square.
     */
    public function markings(array $markings)
    {
        $html = '';
        foreach ($markings['slots'] as $slot) {
            $kind = $slot['kind'] ?? 'marking';
            if ($kind === 'admiralty') {
                $html .= sprintf(
                    '<span class="dk-grade is-claim" role="img" title="%s" aria-label="%s">%s</span>',
                    h($slot['title']),
                    h(__('Admiralty scale: %s', $slot['title'])),
                    h($slot['code'])
                );
                continue;
            }
            if ($kind === 'pinned') {
                foreach ($slot['tags'] as $tag) {
                    $html .= sprintf(
                        '<span class="dk-chip is-tag dk-pin-tag"%s title="%s"><span>%s</span></span>',
                        $this->colourStyle('--tc', $tag['colour']),
                        h($tag['title'] . ' · ' . __('pinned by your profile')),
                        h($tag['value'])
                    );
                }
                continue;
            }
            if (!$slot['present']) {
                $html .= sprintf(
                    '<span class="dk-mk is-none" title="%s"><small>%s</small></span>',
                    h(__('No %s marking', $slot['key'])),
                    h($slot['key'])
                );
                continue;
            }
            $colour = $slot['neutral'] ? '' : $this->colourStyle('--c', $slot['colour']);
            $value = mb_strtolower($slot['value']);
            $plus = strpos($value, '+');
            $html .= sprintf(
                '<span class="dk-mk%s"%s title="%s"><small>%s</small><b>%s</b></span>',
                $colour === '' ? ' is-clear' : '',
                $colour,
                h($slot['name']),
                h($slot['key']),
                // amber+strict reads as amber⁺, the full name in the tooltip.
                h($plus === false ? $value : substr($value, 0, $plus) . '⁺')
            );
        }
        return $html;
    }

    /**
     * One context chip, the profile's tier as a dot (C1).
     */
    public function chip(array $c)
    {
        $pref = $this->priority($c);
        switch ($c['kind']) {
            case 'cluster':
                $title = ($c['relationship'] ? $c['relationship'] . ': ' : '') . $c['galaxy'] . ' › ' . $c['label'];
                $icon = $c['icon'] ? $this->FontAwesome->getClass($c['icon']) : 'fas fa-circle-dot';
                return sprintf(
                    '<span class="dk-chip is-gx%s%s" title="%s"><i class="%s"></i><span>%s</span></span>',
                    $c['attribution'] ? ' is-attr' : '',
                    $pref['class'],
                    h($title . $pref['note']),
                    $icon,
                    h($c['label'])
                );
            case 'technique':
                $title = $c['label'] . '  ' . $c['name'] . ($c['unheld'] ? ' ' . __('(cluster not available here)') : '');
                return sprintf(
                    '<span class="dk-chip is-gx is-tid%s" title="%s"><span>%s</span></span>',
                    $c['unheld'] ? ' is-unheld' : '',
                    h($title),
                    h($c['label'])
                );
            case 'mitigation':
                return sprintf(
                    '<span class="dk-chip is-gx is-mit" title="%s"><i class="fas fa-shield-halved"></i><span>%s</span></span>',
                    h(__('Mitigation %s', $c['label'] . '  ' . $c['name'])),
                    h($c['label'])
                );
            case 'unheld':
                return sprintf(
                    '<span class="dk-chip is-gx is-unheld%s%s" title="%s"><i class="fas fa-circle-dot"></i><span>%s</span></span>',
                    empty($c['attribution']) ? '' : ' is-attr',
                    $pref['class'],
                    h($c['galaxy'] . ' › ' . $c['label'] . ' ' . __('(cluster not available here)') . $pref['note']),
                    h($c['label'])
                );
            case 'tag':
                return sprintf(
                    '<span class="dk-chip is-tag%s"%s title="%s"><span>%s%s</span></span>',
                    $pref['class'],
                    $this->colourStyle('--tc', $c['colour']),
                    h($c['name'] . $pref['note']),
                    $c['namespace'] !== null ? '<small>' . h($c['namespace']) . '</small> ' : '',
                    h($c['label'])
                );
            case 'fold':
                return sprintf(
                    '<span class="dk-chip is-fold" tabindex="0" title="%s">%s</span>',
                    h($this->unresolved($c['count'])),
                    h(__('%s unresolved', $c['count']))
                );
        }
        return '';
    }

    /**
     * A lane's chips and its +N, which events-index-cards.js reveals when
     * the chips do not fit.
     */
    public function chips($lane, array $chips)
    {
        return implode('', array_map([$this, 'chip'], $chips)) . sprintf(
            '<button type="button" class="dk-more" data-dk-lane="%s" aria-haspopup="dialog" aria-expanded="false" aria-label="%s" hidden></button>',
            h($lane),
            h(__('%s: show all', $this->laneLabel($lane)))
        );
    }

    /**
     * The event's whole context as the lists its popover shows, one section
     * per lane, in a template the popover clones.
     */
    public function contextTemplate(array $event, array $rows)
    {
        $sections = '';
        $counts = [
            'attribution' => $rows['attribution_count'],
            'behaviour' => $rows['technique_count'],
            'classification' => 0,
        ];
        foreach (array_keys(self::LANES) as $lane) {
            if (empty($rows[$lane])) {
                continue;
            }
            $sections .= sprintf(
                '<section class="dk-pop-sec" data-dk-lane="%s"><h4>%s%s%s</h4>%s</section>',
                h($lane),
                $this->laneIcon($lane),
                h($this->laneLabel($lane)),
                $counts[$lane] ? ' <small>' . (int)$counts[$lane] . '</small>' : '',
                $this->lists($rows[$lane])
            );
        }
        if ($sections === '') {
            return '';
        }
        return sprintf(
            '<template class="dk-ctx-tpl"><div class="dk-pop-in"><div class="dk-pop-head"><span class="dk-pop-id">#%d</span><b title="%s">%s</b>'
                . '<button type="button" class="dk-pop-x" data-dk-close aria-label="%s"><i class="fas fa-xmark"></i></button></div>%s</div></template>',
            (int)$event['id'],
            h($event['info']),
            h($event['info']),
            h(__('Close')),
            $sections
        );
    }

    public function distribution(array $dist)
    {
        return sprintf(
            '<span class="dk-dist" style="%s" title="%s" aria-label="%s"><i class="%s"></i></span>',
            h($dist['style']),
            h($dist['label']),
            h($dist['label']),
            h($dist['icon'])
        );
    }

    /**
     * Workspaces, sightings, proposals and discussion posts, each only
     * when there are some.
     *
     * @return array html parts
     */
    public function extras(array $event, array $graphs)
    {
        $extras = [];
        if ($graphs) {
            $n = count($graphs);
            $label = $this->plural($n, '%s workspace', '%s workspaces') . ': ' . implode(', ', array_column($graphs, 'name'));
            // Newest first: the preview shows the graph changed last
            $extras[] = sprintf(
                '<a class="dk-graph" href="%s" aria-label="%s" data-intel-graph-thumb="%s" data-revision="%d" data-surface="peek" data-name="%s"%s>'
                    . '<i class="misp-icon misp-icon-analyst-graph misp-simple text-analystGraph"></i> %d</a>',
                h($this->baseurl() . ($n === 1 ? '/workspaces/view/' . $graphs[0]['uuid'] : '/events/view/' . (int)$event['id'])),
                h($label),
                h($graphs[0]['uuid']),
                (int)($graphs[0]['revision'] ?? 0),
                h($graphs[0]['name']),
                $n > 1 ? ' data-note="' . h(__('Changed last of %s workspaces on this event', $n)) . '"' : '',
                $n
            );
        }
        $n = (int)($event['report_count'] ?? 0);
        if ($n) {
            $extras[] = sprintf(
                '<a class="dk-x-report_count dk-report" href="%s" title="%s">'
                    . '<i class="misp-icon misp-icon-report misp-simple text-report"></i> %s</a>',
                h($this->baseurl() . '/events/view/' . (int)$event['id'] . '#tab-reports'),
                h($this->plural($n, '%s event report', '%s event reports')),
                EventCardTool::compactCount($n)
            );
        }
        foreach ([
            ['sightings_count', 'sightings', '<i class="misp-icon misp-icon-sighting misp-simple text-sighting"></i>', '%s sighting', '%s sightings'],
            ['proposals_count', 'proposals', '<i class="fas fa-comment-medical"></i>', '%s proposal', '%s proposals'],
            ['post_count', 'discussion', '<i class="fas fa-comments"></i>', '%s discussion post', '%s discussion posts'],
        ] as [$key, $column, $icon, $one, $many]) {
            $n = (int)($event[$key] ?? 0);
            if ($n) {
                $extras[] = sprintf(
                    '<span class="dk-x-%s" title="%s">%s %s</span>',
                    $column,
                    h($this->plural($n, $one, $many)),
                    $icon,
                    EventCardTool::compactCount($n)
                );
            }
        }
        return $extras;
    }

    /**
     * What the event extends and how many extend it.
     *
     * @return array html parts
     */
    public function extension(array $card, $short = false)
    {
        $ext = [];
        if (!empty($card['extends'])) {
            $parent = $card['extends'];
            $ext[] = $parent['id']
                ? sprintf(
                    '<a href="%s" title="%s"><i class="fas fa-turn-up fa-rotate-90"></i>%s</a>',
                    h($this->baseurl() . '/events/view/' . $parent['id']),
                    h(__('Extends #%s %s', $parent['id'], $parent['info'])),
                    h($short ? '#' . $parent['id'] : __('extends #%s', $parent['id']))
                )
                : sprintf(
                    '<span class="is-unheld" title="%s"><i class="fas fa-turn-up fa-rotate-90"></i>%s</span>',
                    h(__('Extends %s, which is not available here', $parent['uuid'])),
                    h($short ? __('missing') : __('extends an unknown event'))
                );
        }
        if (!empty($card['extended_by'])) {
            $n = (int)$card['extended_by'];
            $ext[] = sprintf(
                '<span title="%s"><i class="fas fa-code-branch"></i>%s</span>',
                h($this->plural($n, 'Extended by %s event', 'Extended by %s events')),
                h($short ? $n : __('extended by %s', $n))
            );
        }
        return $ext;
    }

    public function unresolved($n)
    {
        return __n(
            '%s galaxy tag whose cluster is not available here',
            '%s galaxy tags whose cluster is not available here',
            $n,
            $n
        );
    }

    /**
     * A lane's chips as the folded-tag reference lists (tag-chips), the
     * profile's tier marked on each row as on its chip.
     */
    private function lists(array $chips)
    {
        $clusters = $tags = [];
        $unresolved = 0;
        $tiers = [];
        foreach ($chips as $c) {
            $source = $c['source'] ?? [];
            $tier = $this->priority($c);
            if (isset($source['cluster'])) {
                $clusters[] = $source['cluster'];
                $tagId = (int)($source['cluster']['tag_id'] ?? 0);
            } elseif (isset($source['unheld'])) {
                $clusters[] = $source['unheld'] + ['description' => __('Cluster not available here')];
                $tagId = 0;
            } elseif (isset($source['tag'])) {
                $tags[] = $source['tag'];
                $tagId = (int)($source['tag']['Tag']['id'] ?? 0);
            } else {
                $tagId = 0;
                if ($c['kind'] === 'fold') {
                    $unresolved = $c['count'];
                }
            }
            if ($tagId && $tier['class'] !== '') {
                $tiers[$tagId] = $tier;
            }
        }
        $lists = $this->TagChip->lists([], $clusters) . $this->TagChip->lists($tags, [], ['ownColour' => true]);
        if ($tiers) {
            $lists = preg_replace_callback(
                '/<div class="hg-row([^"]*)" title="([^"]*)" data-tag-id="(\d+)"/',
                function ($m) use ($tiers) {
                    if (!isset($tiers[(int)$m[3]])) {
                        return $m[0];
                    }
                    $tier = $tiers[(int)$m[3]];
                    return sprintf(
                        '<div class="hg-row%s%s" title="%s" data-tag-id="%s"',
                        $m[1],
                        $tier['class'],
                        $m[2] . h($tier['note']),
                        $m[3]
                    );
                },
                $lists
            );
        }
        // Many short lists flow into columns about 360px tall; a list that
        // already spreads over columns of its own keeps the popover to itself.
        $cols = 1;
        if (strpos($lists, 'data-cols="2"') === false && strpos($lists, 'data-cols="3"') === false) {
            $height = 45 * substr_count($lists, 'hg-card-head') + 21 * substr_count($lists, 'class="hg-row');
            $cols = max(1, min(3, (int)ceil($height / 360)));
        }
        return '<div class="dk-pop-body" data-cols="' . $cols . '">' . $lists . '</div>'
            . ($unresolved ? '<div class="dk-pop-note">' . h($this->unresolved($unresolved)) . '</div>' : '');
    }

    private function priority(array $c)
    {
        $tier = $c['priority'] ?? null;
        if ($tier === 'pinned') {
            return ['class' => ' dk-pref', 'note' => ' · ' . __('pinned by your profile')];
        }
        if ($tier === 'preferred') {
            return ['class' => ' dk-pref', 'note' => ' · ' . __('preferred by your profile')];
        }
        return ['class' => '', 'note' => ''];
    }

    private function colourStyle($property, $colour)
    {
        return preg_match('/^#[0-9a-f]{3,8}$/i', (string)$colour) ? sprintf(' style="%s:%s"', $property, h($colour)) : '';
    }

    private function baseurl()
    {
        return $this->_View->viewVars['baseurl'] ?? (string)Configure::read('MISP.baseurl');
    }
}
