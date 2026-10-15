<?php

/**
 * Common functions for the 3 analyst objects
 */
class AnalystDataBehavior extends ModelBehavior
{
    public $SharingGroup;

    private $__current_type = null;

    /** @var array [user id => sharing group ids]; one behavior instance serves every model and user */
    protected $__valid_sharing_groups = [];

    public function setup(Model $Model, $settings = array()) {
        // We want to know whether we're a Note, Opinion or Relationship
        $this->__current_type = $Model->alias;
    }

    // Return the analystData of the current type for a given UUID (this only checks the ACL of the analystData, NOT of the parent.)
    public function fetchForUuid(Model $Model, $uuid, $user = null)
    {
        $conditions = [
            'object_uuid' => $uuid
        ];
        $acl = $this->analystDataConditions($Model, $user);
        if (!empty($acl)) {
            $conditions['AND'][] = $acl;
        }
        return $Model->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => ['Org', 'Orgc', 'SharingGroup'],
        ]);
    }

    // Return the analystData of the current type for a given UUID (this only checks the ACL of the analystData, NOT of the parent.)
    public function fetchForUuids(Model $Model, $uuids, $user = null)
    {
        return $this->__fetchForAddresses($Model, 'object_uuid', $uuids, $user);
    }

    /**
     * The analyst data on values, by the SHA-256 of their text. Like
     * fetchForUuids, only the analyst data's own ACL applies, not the value's.
     *
     * @param Model $Model
     * @param array $hexes
     * @param array|null $user
     * @return array [lowercase hex => [type => rows]]
     */
    public function fetchForSha256s(Model $Model, $hexes, $user = null)
    {
        $hexes = array_map(function ($hex) {
            return strtolower(trim((string)$hex));
        }, (array)$hexes);
        return $this->__fetchForAddresses($Model, 'object_sha256', $hexes, $user);
    }

    private function __fetchForAddresses(Model $Model, $column, $addresses, $user)
    {
        $conditions = [
            $column => $addresses
        ];
        $type = $Model->current_type;
        $acl = $this->analystDataConditions($Model, $user);
        if (!empty($acl)) {
            $conditions['AND'][] = $acl;
        }
        $temp = $Model->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'contain' => ['Org', 'Orgc', 'SharingGroup'],
        ]);
        $results = [];
        foreach ($temp as $result) {
            $results[$result[$type][$column]][$type][] = $result[$type];
        }
        return $results;
    }

    /**
     * The analyst data of the current type that $user may read.
     *
     * @param Model $Model
     * @param array|null $user
     * @return array Conditions, empty for a site admin.
     */
    public function analystDataConditions(Model $Model, $user)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return [];
        }
        $userId = $user['id'] ?? 0;
        if (!isset($this->__valid_sharing_groups[$userId])) {
            $this->__valid_sharing_groups[$userId] = $Model->SharingGroup->authorizedIds($user, true);
        }
        $type = $Model->current_type;
        return [
            'OR' => [
                $type . '.orgc_uuid' => $user['Organisation']['uuid'],
                $type . '.org_uuid' => $user['Organisation']['uuid'],
                $type . '.distribution IN' => [1, 2, 3],
                'AND' => [
                    $type . '.distribution' => 4,
                    $type . '.sharing_group_id IN' => $this->__valid_sharing_groups[$userId]
                ]
            ]
        ];
    }

    public function checkACL()
    {

    }
}
