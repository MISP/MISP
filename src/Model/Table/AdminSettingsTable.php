<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\Validation\Validator;

class AdminSettingsTable extends AppTable
{

    public function changeSetting(string $setting, mixed $value = false): bool|string
    {
        $existing = $this->find()->where(['setting' => $setting])->select(['id'])->first();
        if ($existing) {
            $existing->value = $value;
            if ($this->save($existing)) {
                return true;
            } else {
                return $existing->getErrors();
            }
        } else {
            $newSetting = $this->newEmptyEntity();
            $newSetting->setting = $setting;
            $newSetting->value = $value;
            if ($this->save($newSetting)) {
                return true;
            } else {
                return $newSetting->getErrors();
            }
        }
    }

    public function getSetting(string $setting): mixed
    {
        $setting_object = $this->find()->where(['setting' => $setting])->select(['value'])->first();
        if (!empty($setting_object)) {
            return $setting_object->value;
        } else {
            return false;
        }
    }

    public function updatesDone(bool $blocking = false): bool
    {
        $continue = false;
        while ($continue == false) {
            $db_version = $this->find()->where(['setting' => 'db_version'])->select(['value'])->first();
            $continue = empty($this->findUpgrades($db_version['value']));
            if ($blocking) {
                return $continue;
            }
        }
        return true;
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence('setting', 'create')
            ->notEmptyString('setting');

        $validator
            ->requirePresence('value');
        return $validator;
    }
}
