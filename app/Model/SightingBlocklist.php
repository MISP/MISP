<?php
App::uses('AppModel', 'Model');
App::uses('OrgUuidBlocklist', 'Model');

class SightingBlocklist extends OrgUuidBlocklist
{
    public $useTable = 'sighting_blocklists';

    // Keep the sighting block counters apart from the organisation blocklist
    // ones, otherwise removing an entry here would wipe the counters of the
    // same organisation on the organisation blocklist.
    protected $blockedKeyPrefix = 'misp:sighting_blocklist_blocked';
}
