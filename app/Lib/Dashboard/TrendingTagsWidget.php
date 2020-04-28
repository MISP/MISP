<?php

class TrendingTagsWidget
{
    public $title = 'Trending Tags';
    public $render = 'BarChart';
    public $width = 3;
    public $height = 4;
    public $params = array(
        'time_window' => 'The time window, going back in seconds, that should be included.',
        'exclude' => 'List of substrings to exclude tags by - for example "sofacy" would exclude any tag containing sofacy.',
        'include' => 'List of substrings to include tags by - for example "sofacy" would include any tag containing sofacy.',
        'threshold' => 'Limits the number of displayed tags. Default: 10'
    );
    public $placeholder =
'{
    "time_window": "86400",
    "threshold": 15,
    "exclude": ["tlp:", "pap:"],
    "include": ["misp-galaxy:", "my-internal-taxonomy"]
}';
    public $description = 'Widget showing the trending tags over the past x seconds, along with the possibility to include/exclude tags.';

	public function handler($user, $options = array())
	{
        $this->Event = ClassRegistry::init('Event');
        $params = array(
            'metadata' => 1,
            'timestamp' => time() - (empty($options['time_window']) ? 8640000 : $options['time_window'])
        );
        $threshold = empty($options['threshold']) ? 10 : $options['threshold'];
        $eventIds = $this->Event->filterEventIds($user, $params);
        $params['eventid'] = $eventIds;
        $events = array();
        if (!empty($eventIds)) {
            $events = $this->Event->fetchEvent($user, $params);
        }
        $tags = array();
        $tagColours = array();
        foreach ($events as $event) {
            foreach ($event['EventTag'] as $et) {
                if ($this->checkTag($options, $et['Tag']['name'])) {
                    if (empty($tags[$et['Tag']['name']])) {
                        $tags[$et['Tag']['name']] = 1;
                        $tagColours[$et['Tag']['name']] = $et['Tag']['colour'];
                    } else {
                        $tags[$et['Tag']['name']] += 1;
                    }
                }
            }
        }
        arsort($tags);
        $data['data'] = array_slice($tags, 0, $threshold);
        $data['colours'] = $tagColours;
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
}
