<?php

class TrendingTagsWidget
{
    public $title = 'Trending Tags';
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
