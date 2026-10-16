<?php
App::uses('AppModel', 'Model');

/**
 * An organisation's choice of Analyst Profile.
 *
 * D45 (prd/personas/03-profiles.md §5): opting in to a shipped profile is
 * a selection, not a row in `analyst_profiles`. The first draft stored it
 * as a profile with empty `parameters` and a `selects_uuid`, so that
 * `resolveFor()` could keep its single query; the cost was that
 * `scopeOf()`, the editor, the index and the export each had to learn a
 * row that is not a profile. Two of the three scopes already had a home —
 * a user writes the uuid to `user_settings` under `analyst_profile`, and
 * the instance names one in `ValueIntelligence_instance_profile` — and this is
 * the third, three columns wide.
 *
 * **It holds a uuid and never an id.** A selection outlives the row it
 * names: `updateDefaults()` re-reads the shipped files on every upgrade,
 * and a profile that is deleted and re-imported keeps its uuid and gets a
 * new id. Resolution dereferences the uuid each time and falls through to
 * the next scope when it resolves to nothing (§5), so a stale selection
 * costs a reader the instance default rather than an error.
 *
 * @property Organisation $Organisation
 */
class AnalystProfileSelection extends AppModel
{
    public $useTable = 'analyst_profile_selections';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'Containable',
    );

    public $belongsTo = array(
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
        ),
    );

    public $validate = array(
        'org_id' => array(
            'notBlank' => array('rule' => 'notBlank'),
            'numeric' => array('rule' => 'numeric'),
        ),
        'uuid' => array(
            'uuid' => array('rule' => 'uuid'),
        ),
    );

    public function beforeSave($options = array())
    {
        $this->data[$this->alias]['modified'] = date('Y-m-d H:i:s');
        return true;
    }

    /**
     * The uuid an organisation has selected, or null.
     *
     * @param int|null $orgId
     * @return string|null
     */
    public function forOrg($orgId)
    {
        if (empty($orgId)) {
            return null;
        }
        $row = $this->find('first', array(
            'conditions' => array(
                $this->alias . '.org_id' => $orgId,
            ),
            'fields' => array($this->alias . '.uuid'),
            'recursive' => -1,
        ));
        return empty($row) ? null : $row[$this->alias]['uuid'];
    }

    /**
     * Point an organisation at a profile, replacing whatever it named.
     *
     * The unique index on `org_id` is what makes "one answer per scope"
     * true rather than intended, so this reads the existing row and
     * updates it in place instead of inserting a second one.
     *
     * @param int $orgId
     * @param string $uuid
     * @return bool
     */
    public function selectFor($orgId, $uuid)
    {
        $existing = $this->find('first', array(
            'conditions' => array($this->alias . '.org_id' => $orgId),
            'fields' => array($this->alias . '.id'),
            'recursive' => -1,
        ));
        $this->create();
        $data = array(
            'org_id' => $orgId,
            'uuid' => $uuid,
        );
        if (!empty($existing)) {
            $data['id'] = $existing[$this->alias]['id'];
        }
        return (bool)$this->save(array($this->alias => $data));
    }

    /**
     * @param int $orgId
     * @return bool True whether or not there was one to clear.
     */
    public function clearFor($orgId)
    {
        if (empty($orgId)) {
            return true;
        }
        $this->deleteAll(
            array($this->alias . '.org_id' => $orgId),
            false,
            true
        );
        return true;
    }
}
