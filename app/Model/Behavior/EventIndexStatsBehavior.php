<?php

/**
 * Replaces the events index's pagination count with one aggregate over the
 * same conditions, so the figures above the index cost no extra statement.
 */
class EventIndexStatsBehavior extends ModelBehavior
{
    const WEEK = 604800;

    /** @var array alias => stats of the last count */
    private $stats = [];

    /**
     * @param Model $model
     * @param array $config lastLogin: the reader's previous login, 0 if none
     */
    public function setup(Model $model, $config = [])
    {
        $this->settings[$model->alias] = $config + ['lastLogin' => 0];
        unset($this->stats[$model->alias]);
    }

    public function paginateCount(Model $model, $conditions = null, $recursive = 0, $extra = [])
    {
        $stats = $this->aggregate($model, $conditions);
        $this->stats[$model->alias] = $stats;
        return $stats['total'];
    }

    /**
     * The stats of the last pagination; all zero when the paginator found
     * nothing and never asked for a count.
     *
     * @param Model $model
     * @return array
     */
    public function indexStats(Model $model)
    {
        return $this->stats[$model->alias] ?? self::shape([], $this->settings[$model->alias]['lastLogin']);
    }

    /**
     * @param Model $model
     * @param array|null $conditions
     * @return array
     */
    public function aggregate(Model $model, $conditions)
    {
        $alias = $model->alias;
        $weekAgo = time() - self::WEEK;
        $lastLogin = (int)$this->settings[$alias]['lastLogin'];
        $sum = function ($condition) {
            return 'SUM(CASE WHEN ' . $condition . ' THEN 1 ELSE 0 END)';
        };
        $fields = [
            'COUNT(*) AS total',
            $sum("$alias.published = FALSE") . ' AS unpublished',
            $sum("$alias.publish_timestamp > 0 AND $alias.timestamp > $alias.publish_timestamp") . ' AS pending',
            $sum("$alias.timestamp >= $weekAgo") . ' AS changed_week',
            $sum("$alias.timestamp >= $lastLogin") . ' AS since_last_visit',
            $sum("$alias.first_publication >= $weekAgo") . ' AS new_week',
            "COUNT(DISTINCT $alias.orgc_id) AS creator_orgs",
            "MIN($alias.date) AS date_min",
            "MAX($alias.date) AS date_max",
        ];
        $row = $model->find('first', [
            'fields' => $fields,
            'conditions' => $conditions,
            'recursive' => -1,
            'callbacks' => false,
        ]);
        return self::shape($row[0] ?? [], $lastLogin);
    }

    /**
     * @param array $row
     * @param int $lastLogin
     * @return array
     */
    private static function shape(array $row, $lastLogin)
    {
        $out = ['last_login' => (int)$lastLogin];
        foreach (['total', 'unpublished', 'pending', 'changed_week', 'since_last_visit', 'new_week', 'creator_orgs'] as $key) {
            $out[$key] = (int)($row[$key] ?? 0);
        }
        if (empty($lastLogin)) {
            $out['since_last_visit'] = null;
        }
        $out['date_min'] = $row['date_min'] ?? null;
        $out['date_max'] = $row['date_max'] ?? null;
        return $out;
    }
}
