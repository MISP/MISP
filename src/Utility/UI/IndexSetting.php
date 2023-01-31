<?php
declare(strict_types=1);

namespace App\Utility\UI;

use Cake\Utility\Inflector;

class IndexSetting
{
    public static function getAllSetting($user): array
    {
        $rawSetting = !empty($user->user_settings_by_name['ui.table_setting']['value']) ? json_decode($user->user_settings_by_name['ui.table_setting']['value'], true) : [];
        return $rawSetting;
    }

    public static function getTableSetting($user, $tableId): array
    {
        $rawSetting = IndexSetting::getAllSetting($user);
        if (is_object($tableId)) {
            $tableId = IndexSetting::getIDFromTable($tableId);
        }
        $tableSettings = !empty($rawSetting[$tableId]) ? $rawSetting[$tableId] : [];
        return $tableSettings;
    }

    public static function getIDFromTable(Object $table): string
    {
        return sprintf('%s_index', Inflector::variable(Inflector::singularize(($table->getAlias()))));
    }
}