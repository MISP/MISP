<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

class CorrelationExclusion extends AppModel
{
    public $recursive = -1;

    public $key = 'misp:correlation_exclusions';

    public $actsAs = array(
        'SysLogLogable.SysLogLogable' => array(
                'userModel' => 'User',
                'userKey' => 'user_id',
                'change' => 'full'),
        'Containable',
    );

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
        try {
            $redis = $this->setupRedisWithException();
        } catch (Exception $e) {
            return false;
        }
        $this->Correlation = ClassRegistry::init('Correlation');
        $exclusions = $redis->sMembers($this->key);
        $conditions = [];
        $exclusions = array_chunk($exclusions, 100);
        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;
        }
        $total = count($exclusions);
        foreach ($exclusions as $exclusion_chunk) {
            $i = 0;
            foreach ($exclusion_chunk as $exclusion) {
                $i += 1;
                if (!empty($exclusion)) {
                    if ($exclusion[0] === '%' || substr($exclusion, -1) === '%') {
                        $conditions['OR'][] = ['Correlation.value LIKE' => $exclusion];
                    } else {
                        $conditions['OR']['Correlation.value'][] = $exclusion;
                    }
                }
                if (!empty($conditions)) {
                    $this->Correlation->deleteAll($conditions);
                }
                if ($i % 100 === 0) {
                    $this->Job->saveProgress($jobId, 'Chunk ' . $i . '/' . $total, $i * 100 / $total);
                }
            }
        }
    }
}
