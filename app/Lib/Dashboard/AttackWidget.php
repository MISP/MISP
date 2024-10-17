<?php
class AttackWidget
{
    public $title = 'ATT&CK heatmap';
    public $render = 'Attack';
    public $description = 'Retrieve an ATT&CK (or ATT&CK like) heatmap for the current instance.';
    public $width = 3;
    public $height = 4;
    public $params = [
        'filters' => 'A list of restsearch filters to apply to the heatmap. (dictionary, prepending values with ! uses them as a negation)'
    ];
    public $cacheLifetime = 1200;
    public $autoRefreshDelay = false;
    private $validFilterKeys = [
        'filters'
    ];
    private $Event = null;
    public $placeholder =
'{
    "filters": {
        "attackGalaxy": "mitre-attack-pattern",
        "timestamp": ["2023-01-01", "2023-03-31"],
        "published": [0,1]
    }
}';

    public function handler($user, $options = array())
    {
        $this->Event = ClassRegistry::init('Event');
        $data = null;
        if (!empty($options['filters'])) {
            $data = $this->Event->restSearch($user, 'attack', $options['filters']);
            $data = JsonTool::decode($data->intoString());
        }
        return $data;
    }
}
