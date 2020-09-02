<?php

class RecentSightingsWidget
{
    public $title = 'Recent Sightings';
    public $render = 'SimpleList';
    public $width = 8;
    public $height = 6;
    public $params = array(
        'limit' => 'Maximum amount of sightings to return',
        'last' => 'Limit sightins to last 1d, 12h, ...'
    );
    public $description = 'Widget showing information on recent sightings';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 30;
    public $placeholder =
    '{
        "limit": "10",
        "last": "1d",
    }';

	public function handler($user, $options = array())
	{
        $params = array(
            'last' => empty($options['last']) ? "1d" : $options['last'],
            'limit' => empty($options['limit']) ? "10" : $options['limit']
        );
        $last = $params['last'];
        $limit = $params['limit'];

        $this->Sighting = ClassRegistry::init('Sighting');
        $filters = array( 'last' => $last, 'includeAttribute' => 'true', 'includeEvent' => 'true');
        $data = array();
        $count = 0;

        foreach(json_decode($this->Sighting->restSearch($user, 'json', $filters))->{'response'} as $el) {
            $sighting = $el->{'Sighting'};
            $event = $sighting->{'Event'};
            $attribute = $sighting->{'Attribute'};

            if ($sighting->{'type'} == 0) $type = "Sighting";
            elseif ($sighting->{'type'} == 1) $type = "False positive";
            else $type = "Expiration";

            $output = $attribute->{'value'} . " (id: " . $attribute->{'id'} . ") in " . $event->{'info'} . " (id: " . $event->{'id'} . ")";
            $data[] = array( 'title' => __($type), 'value' => $output, 
                                'html' => sprintf(
                                    ' (Event <a href="%s%s">%s</a>)',
                                    Configure::read('MISP.baseurl') . '/events/view/', $event->{'id'},
                                    $event->{'id'}
                                )
                        );
            ++$count;
            if ($count >= $limit ) break;
        }
        return $data;
	}

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
