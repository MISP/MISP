<?php

class TresholdSightingsWidget
{
    public $title = 'Treshold Sightings';
    public $render = 'SimpleList';
    public $width = 8;
    public $height = 4;
    public $params = array(
        'treshold' => 'Treshold for sightings'
    );
    public $description = 'Widget showing information on sightings above certain treshold';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 30;
    public $placeholder = 
    '{
        "treshold": "10"
    }';

	public function handler($user, $options = array())
	{
        $params = array(
            'treshold' => empty($options['treshold']) ? 10 : $options['treshold'],
        );
        $treshold = $params['treshold'];

        $this->Sighting = ClassRegistry::init('Sighting');

        $filters = array( 'includeAttribute' => 'true', 'includeEvent' => 'true');

        $data = array();
        $sightings_score = array();
        $restSearch = json_decode($this->Sighting->restSearch($user, 'json', $filters))->{'response'};

        foreach($restSearch as $el) {
            $sighting = $el->{'Sighting'};
            $attribute = $sighting->{'Attribute'};
            $event = $sighting->{'Event'};

            if (!array_key_exists($attribute->{'id'}, $sightings_score)) $sightings_score[$attribute->{'id'}] = array( 'value' => $attribute->{'value'},
                                                                                                                'score' => 0,
                                                                                                                'event_title' => $event->{'info'},
                                                                                                                'event_id' => $event->{'id'});
            # Sighting
            if ($sighting->{'type'} == 0) $sightings_score[$attribute->{'id'}]['score'] = $sightings_score[$attribute->{'id'}]['score'] - 1;
            # False Positive
            elseif ($sighting->{'type'} == 1) $sightings_score[$attribute->{'id'}]['score'] = $sightings_score[$attribute->{'id'}]['score'] + 1; 
        }

        foreach($sightings_score as $attribute_id => $s) {
            if ((int)$s['score'] >= (int)$treshold ) {
                $output = "Score: " . $s['score'] . ": " . $s['value'] . " (id: " . $attribute_id . ") in " . $s['event_title'] . " (id: " . $s['event_id'] . ")";
                $data[] = array( 'title' => __("False positive above threshold"), 'value' => $output, 
                                    'html' => sprintf(
                                        ' (Event <a href="%s%s">%s</a>)',
                                        Configure::read('MISP.baseurl') . '/events/view/', $s['event_id'],
                                        $s['event_id']
                                    ));
            };
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
