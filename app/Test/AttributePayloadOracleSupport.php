<?php
/**
 * Boots CakePHP against the configured database and captures what MISP
 * publishes for attributes and proposals: the pubsub, Kafka and workflow
 * payloads. Used by AttributePayloadOracleTest for the behaviour oracle in
 * tests/value_oracle. Every write runs in a transaction that is rolled back.
 */

require_once __DIR__ . '/OracleBootstrap.php';

App::uses('MispAttribute', 'Model');
App::uses('ShadowAttribute', 'Model');
class_exists('MispAttribute');
class_exists('ShadowAttribute');

class PayloadRecorder
{
    private static $published = [];

    public static function add($transport, array $args)
    {
        self::$published[] = ['transport' => $transport, 'args' => $args];
    }

    public static function take()
    {
        $published = self::$published;
        self::$published = [];
        return $published;
    }
}

class PayloadRecordingTransport
{
    public function __call($method, $args)
    {
        PayloadRecorder::add($method, $args);
        return true;
    }
}

trait PayloadRecording
{
    protected function pubToZmq($name)
    {
        return true;
    }

    protected function kafkaTopic($name)
    {
        return 'value-oracle';
    }

    protected function isTriggerCallable($trigger_id): bool
    {
        return true;
    }

    protected function executeTrigger(
        $trigger_id,
        array $data = [],
        array &$blockingErrors = [],
        array $logging = []
    ): bool {
        PayloadRecorder::add('workflow', [$trigger_id, $data, $logging]);
        return true;
    }

    public function getPubSubTool()
    {
        return new PayloadRecordingTransport();
    }

    public function getKafkaPubTool()
    {
        return new PayloadRecordingTransport();
    }
}

class PayloadRecordingAttribute extends MispAttribute
{
    use PayloadRecording;
}

class PayloadRecordingShadowAttribute extends ShadowAttribute
{
    use PayloadRecording;
}

class AttributePayloadOracle
{
    /**
     * @param array $request ['attributes' => [name => id],
     *  'proposals' => [name => id]]
     * @return array Per name: the fetchAttribute() output, then what an edit
     *  and a delete publish (attributes), or what an added copy publishes
     *  (proposals).
     */
    public static function capture(array $request)
    {
        $Attribute = ClassRegistry::init([
            'class' => 'PayloadRecordingAttribute', 'alias' => 'Attribute',
        ]);
        $Shadow = ClassRegistry::init([
            'class' => 'PayloadRecordingShadowAttribute',
            'alias' => 'ShadowAttribute',
        ]);
        $db = $Attribute->getDataSource();
        $out = ['attributes' => [], 'proposals' => []];
        foreach ($request['attributes'] ?? [] as $name => $id) {
            $entry = ['fetch' => $Attribute->fetchAttribute($id)];
            $db->begin();
            try {
                $row = $Attribute->find('first', [
                    'recursive' => -1,
                    'conditions' => ['Attribute.id' => $id],
                ]);
                if (!empty($row)) {
                    PayloadRecorder::take();
                    $row['Attribute']['comment'] = 'value oracle edit';
                    $saved = $Attribute->save($row);
                    $entry['edit'] = [
                        'saved' => !empty($saved),
                        'errors' => $Attribute->validationErrors,
                        'published' => PayloadRecorder::take(),
                    ];
                    // Deleting an attachment would remove its file from disk.
                    $type = $row['Attribute']['type'];
                    if (!$Attribute->typeIsAttachment($type)) {
                        $Attribute->delete($id);
                        $entry['delete'] = PayloadRecorder::take();
                    }
                }
            } finally {
                $db->rollback();
            }
            $out['attributes'][$name] = $entry;
        }
        foreach ($request['proposals'] ?? [] as $name => $id) {
            $entry = [];
            $db->begin();
            try {
                $row = $Shadow->find('first', [
                    'recursive' => -1,
                    'conditions' => ['ShadowAttribute.id' => $id],
                ]);
                if (!empty($row)) {
                    PayloadRecorder::take();
                    unset($row['ShadowAttribute']['id']);
                    $row['ShadowAttribute']['comment'] =
                        'value oracle proposal';
                    $Shadow->create();
                    $saved = $Shadow->save($row);
                    $entry['add'] = [
                        'saved' => !empty($saved),
                        'new_id' => $saved ? $Shadow->id : null,
                        'errors' => $Shadow->validationErrors,
                        'published' => PayloadRecorder::take(),
                    ];
                }
            } finally {
                $db->rollback();
            }
            $out['proposals'][$name] = $entry;
        }
        return $out;
    }
}
