<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

class Correlation extends AppModel
{

    public function correlateValueRouter($value)
    {
        if (Configure::read('MISP.background_jobs')) {
            $job = ClassRegistry::init('Job');
            $job->create();
            $data = array(
                    'worker' => 'default',
                    'job_type' => 'correlateValue',
                    'job_input' => $value,
                    'status' => 0,
                    'retries' => 0,
                    'org_id' => 0,
                    'org' => 0,
                    'message' => 'Recorrelating',
            );
            $job->save($data);
            $jobId = $job->id;
            $process_id = CakeResque::enqueue(
                    'email',
                    'EventShell',
                    ['correlateValue', $value, $jobId],
                    true
            );
            $job->saveField('process_id', $process_id);
            return true;
        } else {
            return $this->correlateValue($value, $jobId);
        }
    }

    public function addAdvancedCorrelations($correlatingAttribute)
    {
        $a = $correlatingAttribute['Attribute'];
        if (Configure::read('MISP.enable_advanced_correlations')) {
            if (in_array($a['type'], array('ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port'))) {
                return $this->Attribute->cidrCorrelation($a);
            } else if ($a['type'] === 'ssdeep' && function_exists('ssdeep_fuzzy_compare')) {
                $this->FuzzyCorrelateSsdeep = ClassRegistry::init('FuzzyCorrelateSsdeep');
                $fuzzyIds = $this->FuzzyCorrelateSsdeep->query_ssdeep_chunks($a['value1'], $a['id']);
                if (!empty($fuzzyIds)) {
                    $ssdeepIds = $this->find('list', array(
                        'recursive' => -1,
                        'conditions' => array(
                            'Attribute.type' => 'ssdeep',
                            'Attribute.id' => $fuzzyIds
                        ),
                        'fields' => array('Attribute.id', 'Attribute.value1')
                    ));
                    $threshold = Configure::read('MISP.ssdeep_correlation_threshold') ?: 40;
                    $attributeIds = array();
                    foreach ($ssdeepIds as $attributeId => $v) {
                        $ssdeep_value = ssdeep_fuzzy_compare($a['value1'], $v);
                        if ($ssdeep_value >= $threshold) {
                            $attributeIds[] = $attributeId;
                        }
                    }
                    return ['Attribute.id' => $attributeIds];
                }
            }
        }
    }

    public function correlateValue($value, $jobId)
    {
        $valueConditions = [
            'Attribute.value1' => $exclusion['CorrelationExclusion']['value'],
            'AND' => [
                'Attribute.value2' => $exclusion['CorrelationExclusion']['value'],
                'NOT' => ['Attribute.type' => $this->Attribute->primaryOnlyCorrelatingTypes]
            ]
        ];
        $conditions = [
            'OR' => $valueConditions,
            'NOT' => [
                'Attribute.type' => $this->Attribute->nonCorrelatingTypes,
            ],
            'Attribute.disable_correlation' => 0,
            'Event.disable_correlation' => 0,
            'Attribute.deleted' => 0
        ];
        $this->Attribute = ClassRegistry::init('Attribute');
        $correlatingAttributes[$k] = $this->Attribute->find('all', [
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => [
                'Attribute.event_id',
                'Attribute.id',
                'Attribute.distribution',
                'Attribute.sharing_group_id',
                'Attribute.value1',
                'Attribute.value2',
            ],
            'contain' => [
                'Event' => [
                    'fields' => ['Event.id', 'Event.date', 'Event.info', 'Event.org_id', 'Event.distribution', 'Event.sharing_group_id', 'Event.disable_correlation']
                ]
            ],
            'order' => [],
        ]);
        $count = count($correlatingAttributes);
        $correlations = [];
        foreach ($correlatingAttributes as $k => $correlatingAttribute) {
            if (
                in_array($correlatingAttribute2['Attribute']['type'], $this->Attribute->nonCorrelatingTypes) ||
                !empty($correlatingAttribute['Event']['disable_correlation'])
            ) {
                continue;
            }
            foreach ($correlatingAttribute as $k2 => $correlatingAttribute2) {
                if (
                    $correlatingAttribute['Attribute']['event_id'] === $correlatingAttribute2['Attribute']['event_id'] ||
                    !empty($correlatingAttribute2['Event']['disable_correlation']) ||
                    in_array($correlatingAttribute2['Attribute']['type'], $this->Attribute->nonCorrelatingTypes)
                ) {
                    continue;
                }
                $correlations[] = array(
                    'value' => $value,
                    '1_event_id' => $correlatingAttribute['Event']['id'],
                    '1_attribute_id' => $correlatingAttribute['Attribute']['id'],
                    'event_id' => $correlatingAttribute2['Attribute']['event_id'],
                    'attribute_id' => $correlatingAttribute2['Attribute']['id'],
                    'org_id' => $correlatingAttribute2['Event']['org_id'],
                    'distribution' => $correlatingAttribute2['Event']['distribution'],
                    'a_distribution' => $correlatingAttribute2['Attribute']['distribution'],
                    'sharing_group_id' => $correlatingAttribute2['Event']['sharing_group_id'],
                    'a_sharing_group_id' => $correlatingAttribute2['Attribute']['sharing_group_id'],
                    'date' => $correlatingAttribute2['Event']['date'],
                    'info' => $correlatingAttribute2['Event']['info']
                );
            }
            $correlations = $this->addAdvancedCorrelations($correlatingAttribute);
        }

        if (Configure::read('MISP.deadlock_avoidance')) {
            return $this->saveMany($correlations, array(
                'atomic' => false,
                'callbacks' => false,
                'deep' => false,
                'validate' => false,
                'fieldList' => $fields,
            ));
        } else {
            $db = $this->getDataSource();
            return $db->insertMulti('correlations', $fields, $correlations);
        }
    }
}
