<?php
App::uses('AppModel', 'Model');

class CorrelationExclusion extends AppModel
{
    public $recursive = -1;

    public $key = 'misp:correlation_exclusions';

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array(
                'userModel' => 'User',
                'userKey' => 'user_id',
                'change' => 'full'),
        'Containable',
    );

    public $validate = [
        'value' => [
            'uniqueValue' => [
                'rule' => 'isUnique',
                'message' => 'Value is already in the exclusion list.'
            ]
        ]
    ];

    public function afterSave($created, $options = array())
    {
        $this->cacheValues();
    }

    public function beforeDelete($cascade = true)
    {
        $exclusion = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'id' => $this->id
            ]
        ]);
        $this->Correlation = ClassRegistry::init('Correlation');
        if (!empty($exclusion)) {
            $this->Correlation->correlateValueRouter($exclusion['CorrelationExclusion']['value']);
        }
    }

    public function afterDelete()
    {
        $this->cacheValues();
    }

    public function cacheValues()
    {
        try {
            $redis = RedisTool::init();
        } catch (Exception $e) {
            return false;
        }
        RedisTool::unlink($redis, $this->key);
        $exclusions = $this->find('column', [
            'fields' => ['value']
        ]);
        $redis->sAddArray($this->key, $exclusions);
    }

    public function cleanRouter($user)
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $user,
                Job::WORKER_DEFAULT,
                'clean_correlation_exclusions',
                '',
                __('Cleaning up excluded correlations.')
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'cleanExcludedCorrelations',
                    $jobId
                ],
                true,
                $jobId
            );
        } else {
            $this->clean();
        }
    }

    public function clean($jobId = false)
    {
        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;
        }
        $values = $this->find('column', [
            'recursive' => -1,
            'fields' => ['value']
        ]);
        $this->Correlation = ClassRegistry::init('Correlation');
        foreach ($values as $value) {
            $this->Correlation->purgeByValue($value);
        }
        if ($jobId) {
            $this->Job->saveProgress($jobId, 'Job done.', 100);
        }
    }
}
