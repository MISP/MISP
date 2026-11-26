<?php

/**
 * The column list of a find without a field list, cached by the columns the
 * model describes.
 *
 * DboSource::fields() caches that list under a key without the table's
 * columns, and the method cache is persisted (`_cake_core_`, written back by
 * every process on exit). After a column is added or dropped, every process
 * kept selecting the old ones until the core cache was cleared, and a process
 * that had loaded the old list wrote it back after a clear. Keyed by the
 * columns, a list from before a schema change is never hit again.
 */
trait CurrentColumnListTrait
{
    /**
     * @param Model $Model
     * @param string|null $alias
     * @param bool $quote
     * @param Closure $build The parent's fields(), with no field list.
     * @return array
     */
    protected function currentColumnList(Model $Model, $alias, $quote, Closure $build)
    {
        $key = $this->cacheMethodHasher(serialize(array(
            $alias,
            get_class($Model),
            $Model->alias,
            $Model->getVirtualField(),
            $quote,
            ConnectionManager::getSourceName($this),
            $Model->schemaName,
            $Model->table,
            array_keys((array)$Model->schema()),
        )));
        $list = $this->cacheMethod(__FUNCTION__, $key);
        if ($list !== null) {
            return $list;
        }
        $this->cacheMethods = false;
        try {
            $list = $build();
        } finally {
            $this->cacheMethods = true;
        }
        return $this->cacheMethod(__FUNCTION__, $key, $list);
    }
}
