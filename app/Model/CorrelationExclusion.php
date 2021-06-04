<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

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
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        $redis->del($this->key);
        $exclusions = $this->find('column', [
            'fields' => ['value']
        ]);
        $redis->sAddArray($this->key, $exclusions);
    }

    public function cleanRouter($user)
    {
        if (Configure::read('MISP.background_jobs')) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->create();
            $data = [
                    'worker' => 'default',
                    'job_type' => 'clean_correlation_exclusions',
                    'job_input' => '',
                    'status' => 0,
                    'retries' => 0,
                    'org' => $user['Organisation']['name'],
                    'message' => __('Cleaning up excluded correlations.'),
            ];
            $this->Job->save($data);
            $jobId = $this->Job->id;
            $process_id = CakeResque::enqueue(
                    'default',
                    'AdminShell',
                    ['cleanExcludedCorrelations', $jobId],
                    true
            );
            $this->Job->saveField('process_id', $process_id);
            $message = __('Cleanup queued for background execution.');
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
        $query = sprintf(
            'DELETE FROM correlations where (%s) or (%s);',
            sprintf(
                'value IN (%s)',
                'SELECT correlation_exclusions.value FROM correlation_exclusions WHERE correlations.value = correlation_exclusions.value'
            ),
            sprintf(
                'EXISTS (SELECT NULL FROM correlation_exclusions WHERE (%s) OR (%s))',
                "correlations.value LIKE CONCAT('%', correlation_exclusions.value)",
                "correlations.value LIKE CONCAT(correlation_exclusions.value, '%')"
            )
        );
        $this->query($query);
        $this->Job->saveProgress($jobId, 'Job done.', 100);
    }
}
