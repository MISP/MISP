<?php
class OrgsContributorsGeneric
{
    public $render = 'OrgsPictures';
    public $width = 4;
    public $height = 4;
    public $cacheLifetime = 3600;
    public $autoRefreshDelay = false;
    public $params = array (
        'blocklist_orgs' => 'A list of organisation names to filter out',
        'timeframe' => 'Number of days considered for the query (30 by default)'
    );
    // Partial $schema (the in-tree norm — e.g. NewOrgsWidget schemas
    // only `filter` of its ~12 params): `timeframe` gets a typed int
    // field so the three OrgsContributors* subclasses no longer fall
    // wholly to the kv-tier. `blocklist_orgs` stays on the kv-tier
    // (chip input for arrays, DD-06): it's a flat list of org-name
    // strings consumed verbatim by handler()'s in_array() check, and
    // the `org_filter` canonical translates to a structured
    // {orgs:[...], match_via} shape that the handler doesn't read —
    // wiring it would mean rewriting the shared handler.
    public $schema = array(
        'timeframe' => array(
            'type' => 'int',
            'default' => 30,
            'help' => 'Number of days back to consider for the query.',
        ),
    );
    public $placeholder =
'{
    "blocklist_orgs": ["Orgs to filter"],
    "timeframe": "30"
}';

    /**
     * Enumerating the organisation directory is exactly what
     * `Security.hide_organisation_index_from_users` exists to prevent, and
     * `organisations/index` refuses outright when it is set. Mirror that
     * predicate here - the widget renders a list of identifiable
     * organisations, and `renderWidget`'s `exportjson` hands back this
     * handler's return value verbatim, so without this the widget is a way
     * around the setting. Kept in sync with the `organisation_index` dynamic
     * check in ACLComponent.php:1171.
     */
    public function checkPermissions($user)
    {
        if (Configure::read('Security.hide_organisation_index_from_users')) {
            return !empty($user['Role']['perm_sharing_group']);
        }
        return true;
    }

    //This is the default filter - to be overridden in children classes
    protected function filter($user, $org, $options) {
        return true;
    }

    public function handler($user, $options = array())
    {
        $this->Org = ClassRegistry::init('Organisation');
        $this->Event = ClassRegistry::init('Event');
        if (!empty($options['timeframe'])) {
            $days = (int) $options['timeframe'];
        } else {
            $days = 30;
        }
        $start_timestamp = $this->Event->resolveTimeDelta($days.'d');

        // Only the three fields the OrgsPictures renderer and the subclass
        // filters actually use. A bare find('all') returned whole rows -
        // created_by, contacts, local, date_modified and the rest - none of
        // which is rendered, but all of which `exportjson` handed back.
        $orgs = $this->Org->find('all', array(
            'recursive' => -1,
            'conditions' => array('Organisation.local' => 1),
            'fields' => array('Organisation.id', 'Organisation.name', 'Organisation.uuid'),
        ));
        $result = array();
        foreach($orgs as $org) {
            if(!empty($options['blocklist_orgs']) && in_array($org['Organisation']['name'], $options['blocklist_orgs'])) {
                continue;
            }
            if ($this->filter($user, $org, $start_timestamp)) {
                $result[] = $org;
            }
        }
        return $result;
    }
}
