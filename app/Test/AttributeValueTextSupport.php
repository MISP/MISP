<?php
/**
 * The value text columns of attributes and proposals, for the gated tests that
 * run on either side of the text-column drop.
 */
class AttributeValueTextSupport
{
    /** @var array table => whether it has value1 and value2 */
    private static $present = [];

    /**
     * @param DboSource $db
     * @param string $table
     * @return bool
     */
    public static function present(DboSource $db, $table)
    {
        if (!isset(self::$present[$table])) {
            $statement = $db->rawQuery("SHOW COLUMNS FROM `$table` WHERE Field IN ('value1', 'value2')");
            self::$present[$table] = count($statement->fetchAll(PDO::FETCH_ASSOC)) === 2;
            $statement->closeCursor();
        }
        return self::$present[$table];
    }

    /**
     * Runs a statement that points the stored text away from the dictionary,
     * so that a read of the text columns shows. Once they are dropped there is
     * nothing to point away, and a read is an SQL error.
     *
     * @param DboSource $db
     * @param string $table
     * @param string $sql
     * @return void
     */
    public static function diverge(DboSource $db, $table, $sql)
    {
        if (self::present($db, $table)) {
            $statement = $db->rawQuery($sql);
            if ($statement instanceof PDOStatement) {
                $statement->closeCursor();
            }
        }
    }

    /**
     * The text a value id column gives back, as an SQL expression: what the
     * text column held before the drop.
     *
     * @param string $alias The attribute or proposal table's alias.
     * @param string $column value1 or value2.
     * @return string
     */
    public static function text($alias, $column)
    {
        return sprintf(
            "COALESCE((SELECT v.value FROM attribute_values v WHERE v.id = %s.%s_id), '')",
            $alias,
            $column
        );
    }
}
