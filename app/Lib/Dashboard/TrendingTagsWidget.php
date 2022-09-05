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
    public $cacheLifetime = 600;

	public function handler($user, $options = array())
	{
	    /** @var Event $eventModel */
        $eventModel = ClassRegistry::init('Event');
        $threshold = empty($options['threshold']) ? 10 : $options['threshold'];
        $params = [
            'timestamp' => time() - (empty($options['time_window']) ? 8640000 : $options['time_window']),
        ];
        $eventIds = $eventModel->filterEventIds($user, $params);

        $tags = [];
        $tagColours = [];
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
        }

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
