<?php
/**
* Org Events widget which reports the number of events created monthly by each local organizations
*
*/
class OrgEventsWidget
{
    public $title = 'Org Events';
    public $category = 'events';
    public $render = 'MultiLineChart';
    public $width = 8;
    public $height = 6;
    public $description = 'A graph to show the monthly number of events per organisation';
    public $cacheLifetime = 10;
    public $autoRefreshDelay = false;
    public $params = array (
        'blocklist_orgs' => 'A list of organisation names to filter out',
        'months' => 'Number of past months to consider for the graph',
        'logarithmic' => 'Visualize data on logarithmic scale',
        'threat_level' => 'A list of threat levels (1=High, 2=Medium, 3=Low, 4=Undefined) to filter events by. Accepts an int array or single int. Empty / unset = no filter.',
        'analysis' => 'A list of analysis stages (0=Initial, 1=Ongoing, 2=Complete) to filter events by. Accepts an int array or single int. Empty / unset = no filter.',
    );
    public $schema = array(
        'months' => array(
            'type' => 'int',
            'default' => 6,
            'help' => 'Number of past months to include in the graph.',
        ),
        'logarithmic' => array(
            'type' => 'bool',
            'default' => true,
            'help' => 'Display the y-axis on a logarithmic scale.',
        ),
        'threat_level' => array(
            'type' => 'threat_level_filter',
            'help' => 'Filter events by threat level. Bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.',
        ),
        'analysis' => array(
            'type' => 'analysis_filter',
            'help' => 'Filter events by analysis stage (Initial / Ongoing / Complete). Bulk-edited via the dashboard toolbar when at least one widget on the board declares this canonical.',
        ),
    );

    public $placeholder =
'{
    "blocklist_orgs": ["Orgs to filter"],
    "months": "6",
    "logarithmic": "true"
}';





    /*
    * Target_month must be from 1 to 12
    * Target year must be 4 digits
    *
    * Canonical filters ($threatLevels, $analysisStages) apply as
    * native Event.* IN conditions on the fetchSimpleEventIds call —
    * unlike EventStreamWidget which uses fetchEvent (no native filter
    * inputs for these columns, forcing a PHP post-filter + overshoot),
    * this widget's Event-conditions path admits the filters at SQL
    * level. Empty arrays skip the respective clause entirely.
    */
    private function org_events_count($user, $org, $target_month, $target_year, $threatLevels = array(), $analysisStages = array()) {
        $events_count = 0;

        $start_date = $target_year.'-'.$target_month.'-01';
        if($target_month == 12) {
            $end_date = ($target_year+1).'-01-01';
        } else {
            $end_date = $target_year.'-'.($target_month+1).'-01';
        }
        $conditions = array('Event.orgc_id' => $org['Organisation']['id'], 'Event.date >=' => $start_date, 'Event.date <' => $end_date);
        if (!empty($threatLevels)) {
            $conditions['Event.threat_level_id'] = $threatLevels;
        }
        if (!empty($analysisStages)) {
            $conditions['Event.analysis'] = $analysisStages;
        }

        //This is required to enforce the ACL (not pull directly from the DB)
        $eventIds = $this->Event->fetchSimpleEventIds($user, array('conditions' => $conditions));

        if(!empty($eventIds)) {
            $params = array('Event.id' => $eventIds);
            $events = $this->Event->find('all', array('conditions' => array('AND' => $params)));
            foreach($events as $event) {
                $events_count+= 1;
            }
        }
        return $events_count;
    }

    private function filter_ghost_orgs(&$data, $orgs){
        foreach ($data['data'] as &$item) {
            foreach(array_keys($orgs) as $org_name) {
                unset($item[$org_name]);
            }
        }
    }

    public function handler($user, $options = array())
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Org = ClassRegistry::init('Organisation');
        $this->Event = ClassRegistry::init('Event');
        // Phase 3 canonical filter — threat_level. The adapter normalises
        // the wire shape to an int array before this handler runs, but
        // we defensively re-coerce so paths that bypass the adapter
        // (direct handler() invocation, REST clients posting legacy
        // scalar values) still produce a clean int[] for the SQL IN
        // clause. Empty / unset => no filter applied.
        $coerceLevels = function ($raw) {
            $arr = is_array($raw) ? $raw : array($raw);
            $out = array();
            foreach ($arr as $v) {
                if (is_int($v)
                    || (is_string($v) && is_numeric($v))
                    || (is_float($v) && is_finite($v))) {
                    $out[] = (int)$v;
                }
            }
            return $out;
        };
        $allowedThreat = !empty($options['threat_level'])
            ? $coerceLevels($options['threat_level']) : array();
        // analysis uses isset/!== '' not !empty() — 0=Initial is a
        // valid filter value and !empty(0) is true while !empty([0])
        // is true too, but a scalar 0 posted by a legacy REST client
        // would be silently dropped by the !empty() shortcut.
        $allowedAnalysis = isset($options['analysis']) && $options['analysis'] !== ''
            ? $coerceLevels($options['analysis']) : array();
        $orgs = $this->Org->find('all', array( 'conditions' => array('Organisation.local' => 1)));
        $current_month = date('n');
        $current_year = date('Y');
        $limit = 6; // months
        if(!empty($options['months'])) {
            $limit = (int) ($options['months']);
        }
        $offset = 0;
        $ghost_orgs = array(); // track orgs without any contribution
        // We start by putting all orgs_id in there:
        foreach($orgs as $org) {
            // We check for blocklisted orgs
            if(!empty($options['blocklist_orgs']) && in_array($org['Organisation']['name'], $options['blocklist_orgs'])) {
                unset($orgs[$offset]);
            } else {
                $ghost_orgs[$org['Organisation']['name']] = true;
            }
            $offset++;
        }
        $data = array();
        $data['data'] = array();
        for ($i=0; $i < $limit; $i++) {
            $target_month = $current_month - $i;
            $target_year = $current_year;
            if ($target_month < 1) {
                $target_month += 12;
                $target_year -= 1;
            }
            $item = array();
            $item ['date'] = $target_year.'-'.$target_month.'-01';
            foreach($orgs as $org) {
                    $count = $this->org_events_count($user, $org, $target_month, $target_year, $allowedThreat, $allowedAnalysis);
                    // Phase 2 fix: the prior strict-string check (=== "true" /
                    // === "1") silently dropped the log-scale branch once the
                    // configure form started writing real PHP booleans per
                    // $schema['logarithmic']['type'] = 'bool', and the else-if
                    // repeated the same conditions as the if, leaving a
                    // silent fall-through gap where neither branch fired.
                    $logRaw = $options['logarithmic'] ?? true; // schema default
                    $isLogarithmic = ($logRaw === true || $logRaw === 1
                        || $logRaw === '1' || $logRaw === 'true');
                    if ($isLogarithmic) {
                        $item[$org['Organisation']['name']] = (int) round(log($count, 1.1));
                    } else {
                        $item[$org['Organisation']['name']] = $count;
                    }
                    // if a positive score is detected at least once it's enough to be
                    // considered for the graph
                    if($count > 0) {
                        unset($ghost_orgs[$org['Organisation']['name']]);
                    }
                }
            $data['data'][] = $item;
        }
        $this->filter_ghost_orgs($data, $ghost_orgs);
        return $data;
    }
}
