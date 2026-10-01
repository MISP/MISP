<?php
App::uses('AppModel', 'Model');
App::uses('OrgUuidBlocklist', 'Model');

class OrgBlocklist extends OrgUuidBlocklist
{
    public $useTable = 'org_blocklists';
}
