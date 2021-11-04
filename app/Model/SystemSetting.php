<?php
App::uses('AppModel', 'Model');
App::uses('JsonTool', 'Tools');

class SystemSetting extends AppModel
{
    public $actsAs = [
        'SysLogLogable.SysLogLogable' => [
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ],
        'AuditLog'
    ];

    public $primaryKey = 'setting';

    public function getSettings()
    {
        $settings = $this->find('list', [
            'fields' => ['SystemSetting.setting', 'SystemSetting.value'],
        ]);
        return array_map(['JsonTool', 'decode'], $settings);
    }

    /**
     * @param string $setting
     * @param mixed $value
     * @throws Exception
     */
    public function setSetting($setting, $value)
    {
        $valid = $this->save(['SystemSetting' => [
            'setting' => $setting,
            'value' => JsonTool::encode($value),
        ]]);
        if (!$valid) {
            throw new Exception("Could not save system setting `$setting` because of validation errors: " . JsonTool::encode($this->validationErrors));
        }
    }
}
