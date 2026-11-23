<?php

App::uses('AbstractMigration', 'Migration');

/**
 * Delete the auth keys and settings that deleted users left behind: a user
 * given the same id again would inherit them. Deleting a user now takes both
 * along.
 */
class Migration_20261109_105432_delete_orphaned_user_rows extends AbstractMigration
{
    public $description = 'Delete the auth keys and settings of deleted users';

    /**
     * Only rows of users that no longer exist are touched.
     *
     * @var bool
     */
    public $requiresLogout = false;

    /**
     * No DDL.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
    }

    /**
     * A re-run finds nothing left to delete.
     *
     * @return bool
     */
    public function afterUp()
    {
        $deleted = array();
        foreach (array('AuthKey', 'UserSetting') as $modelName) {
            $Model = ClassRegistry::init($modelName);
            $ids = $Model->find('column', array(
                'fields' => array($modelName . '.id'),
                'joins' => array(array(
                    'table' => 'users',
                    'alias' => 'User',
                    'type' => 'LEFT',
                    'conditions' => array('User.id = ' . $modelName . '.user_id'),
                )),
                'conditions' => array('User.id' => null),
            ));
            foreach (array_chunk($ids, 1000) as $chunk) {
                if (!$Model->deleteAll(array($modelName . '.id' => $chunk), false, false)) {
                    return false;
                }
            }
            $deleted[] = count($ids);
        }
        if (array_sum($deleted) > 0) {
            ClassRegistry::init('Log')->createLogEntry(
                'SYSTEM',
                'update_database',
                'Server',
                0,
                __('Deleted %s auth keys and %s user settings of deleted users.', $deleted[0], $deleted[1])
            );
        }
        return true;
    }
}
