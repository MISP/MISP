<?php

class TrendingTagsWidget
{
    public $title = 'Trending Tags';
    public $category = 'tags';
    public $render = 'BarChart';
    public $width = 3;
    public $height = 4;
    public $params = array(
        'time_window' => 'The time window, going back in seconds, that should be included. (allows for filtering by days - example: 5d. -1 Will fetch all historic data)',
        'exclude' => 'List of substrings to exclude tags by - for example "sofacy" would exclude any tag containing sofacy.',
        'include' => 'List of substrings to include tags by - for example "sofacy" would include any tag containing sofacy.',
        'threshold' => 'Limits the number of displayed tags. Default: 10',
        'filter_event_tags' => 'Filters to be applied on event tags',
        'over_time' => 'Toggle the trending to be over time',
        'distribution' => 'Filter source events by distribution level. Integer array, subset of {0..5} (0=Org only, 1=Community, 2=Connected, 3=All, 4=Sharing group, 5=Inherit). Empty / missing = no filter.',
    );
    public $schema = array(
        'time_window' => array(
            'type' => 'time_window',
            'default' => 'P7D',
            'help' => 'Time window over which to aggregate (last N days/hours, or all time).',
        ),
        'tag_filter' => array(
            'type' => 'tag_filter',
            'help' => 'Substring patterns that include/exclude tags from the trending list. "tlp:" matches every TLP tag.',
        ),
        'distribution' => array(
            'type' => 'distribution_filter',
            'help' => 'Restrict the source events by distribution level. Empty selection = no filter.',
        ),
        'threshold' => array(
            'type' => 'int',
            'default' => 10,
            'help' => 'Limits the number of displayed tags.',
        ),
        'over_time' => array(
            'type' => 'bool',
            'default' => false,
            'help' => 'Plot trending tags over time as a multi-line chart instead of a single-snapshot bar chart.',
        ),
    );
    public $placeholder =
    '{
    "time_window": "7d",
    "threshold": 15,
    "exclude": ["tlp:", "pap:"],
    "include": ["misp-galaxy:", "my-internal-taxonomy"],
    "filter_event_tags": ["misp-galaxy:threat-actor="APT 29"],
}';
    public $description = 'Widget showing the trending tags over the past x seconds, along with the possibility to include/exclude tags.';
    public $cacheLifetime = 3;

	public function handler($user, $options = array())
	{
	    /** @var Event $eventModel */
        $eventModel = ClassRegistry::init('Event');
        $threshold = empty($options['threshold']) ? 10 : $options['threshold'];
        if (!empty($options['time_window']) && is_string($options['time_window']) && substr($options['time_window'], -1) === 'd') {
            $time_window = ((int)substr($options['time_window'], 0, -1)) * 24 * 60 * 60;
        } else {
            $time_window = empty($options['time_window']) ? (7 * 24 * 60 * 60) : (int)$options['time_window'];
        }
        $params = $time_window === -1 ? [] : ['timestamp' => time() - $time_window];

        if (!empty($options['filter_event_tags'])) {
            $params['event_tags'] = $options['filter_event_tags'];
        }
        $eventIds = $eventModel->filterEventIds($user, $params);

        // Phase 3 canonical distribution_filter — narrow the event-id
        // list by Event.distribution when the option is non-empty.
        // filterEventIds doesn't accept `distribution` in its
        // simple_params dispatch (would be a MISP-core touch), so the
        // narrowing happens here as a post-step: one `find('list')`
        // against Event with the already-ACL-filtered eventIds as the
        // base set, plus an IN clause on Event.distribution. ACL-safe
        // because the input set was already filtered by
        // filterEventIds (which honours the user's permissions).
        if (!empty($options['distribution']) && !empty($eventIds)) {
            $distribution = is_array($options['distribution'])
                ? array_values(array_filter($options['distribution'], 'is_numeric'))
                : (is_numeric($options['distribution']) ? [(int)$options['distribution']] : []);
            if (!empty($distribution)) {
                $eventIds = array_keys($eventModel->find('list', [
                    'recursive' => -1,
                    'conditions' => [
                        'Event.id' => $eventIds,
                        'Event.distribution' => $distribution,
                    ],
                    'fields' => ['Event.id', 'Event.id'],
                ]));
            }
        }

        $tagColours = [];
        $allTags = [];
        $data = [];
        $this->render = $this->getRenderer($options);
        if (!empty($options['over_time'])) {

            $tagOvertime = [];
            if (!empty($eventIds)) {
                $events = $eventModel->fetchEvent($user, [
                    'eventid' => $eventIds,
                    'order' => 'Event.timestamp',
                    'metadata' => 1
                ]);

                foreach ($events as $event) {
                    $timestamp = $event['Event']['timestamp'];
                    $timestamp = strftime('%Y-%m-%d', $timestamp);
                    foreach ($event['EventTag'] as $tag) {
                        $tagName = $tag['Tag']['name'];
                        if (isset($tagOvertime[$timestamp][$tagName])) {
                            $tagOvertime[$timestamp][$tagName]++;
                        } else if ($this->checkTag($options, $tagName)) {
                            $tagOvertime[$timestamp][$tagName] = 1;
                            $tagColours[$tagName] = $tag['Tag']['colour'];
                            $allTags[$tagName] = $tagName;
                        }
                    }
                }
            }

            // Honor $threshold in the over_time path too. Bar path
            // already slices to top-N; without the same cap here a
            // multi-line chart surfaces every tag that appears in the
            // window, which makes the legend unusable and contradicts
            // the param's help text ("Limits the number of displayed
            // tags."). Rank tags by total count across the full window
            // so the per-line series picks the most-frequent overall;
            // a per-row top-N would give a different tag set per date
            // and make the line chart meaningless.
            $totals = array_fill_keys(array_keys($allTags), 0);
            foreach ($tagOvertime as $date => $tagCount) {
                foreach ($tagCount as $tagName => $count) {
                    if (isset($totals[$tagName])) {
                        $totals[$tagName] += $count;
                    }
                }
            }
            arsort($totals);
            $topTagNames = array_slice(array_keys($totals), 0, $threshold);
            $allTags = array_combine($topTagNames, $topTagNames);

            $data['data'] = [];
            foreach($tagOvertime as $date => $tagCount) {
                $item = [];
                $item['date'] = $date;
                foreach ($allTags as $tagName) {
                    if (!empty($tagCount[$tagName])) {
                        $item[$tagName] = $tagCount[$tagName];
                    } else {
                        $item[$tagName] = 0;
                    }
                }
                $data['data'][] = $item;
            }
            uasort($data['data'], function ($a, $b) {
                return ($a['date'] < $b['date']) ? -1 : 1;
            });
            $data['data'] = array_values($data['data']);
            // Surface the tag colours so MultiLineChart can use the
            // widget's own colour metadata; bar path already does this
            // on line 132. Without it the over_time renderer falls back
            // to the default ECharts palette which loses the
            // tag-colour-as-identity that users rely on (e.g. TLP).
            $data['colours'] = array_intersect_key($tagColours, $allTags);
            return $data;
        } else {
            $tags = [];
            if (!empty($eventIds)) {
                $eventTags = $eventModel->EventTag->find('all', [
                    'conditions' => ['EventTag.event_id' => $eventIds],
                    'contain' => ['Tag' => ['fields' => ['name', 'colour']]],
                    'recursive' => -1,
                    'fields' => ['id'],
                ]);
    
                foreach ($eventTags as $eventTag) {
                    $tagName = $eventTag['Tag']['name'];
                    if (isset($tags[$tagName])) {
                        $tags[$tagName]++;
                    } else if ($this->checkTag($options, $tagName)) {
                        $tags[$tagName] = 1;
                        $tagColours[$tagName] = $eventTag['Tag']['colour'];
                    }
                }
    
                arsort($tags);
                $data['data'] = array_slice($tags, 0, $threshold);
                $data['colours'] = $tagColours;
            }
    
        }
        return $data;
	}

    private function checkTag($options, $tag)
    {
        if (!empty($options['exclude'])) {
            foreach ($options['exclude'] as $exclude) {
                if (strpos($tag, $exclude) !== false) {
                    return false;
                }
            }
        }
        if (!empty($options['include'])) {
            foreach ($options['include'] as $include) {
                if (strpos($tag, $include) !== false) {
                    return true;
                }
            }
            return false;
        } else {
            return true;
        }
    }

    public function getRenderer(array $options)
    {
        return !empty($options['over_time']) ? 'MultiLineChart' : 'BarChart';
    }
}
