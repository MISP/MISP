<?php
App::uses('AppModel', 'Model');
App::uses('AnalystData', 'Model');
class Relationship extends AnalystData
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
            'AnalystData'
    );

    public $current_type = 'Relationship';
    public $current_type_id = 2;

    public $validate = array(
    );

    /** @var object|null */
    protected $Event;
    /** @var object|null */
    protected $Attribute;
    /** @var object|null */
    protected $Object;
    /** @var object|null */
    protected $Note;
    /** @var object|null */
    protected $Opinion;
    /** @var object|null */
    protected $Relationship;
    /** @var object|null */
    protected $User;
    /** @var array|null */
    private $__currentUser;

    public function afterFind($results, $primary = false)
    {
        $results = parent::afterFind($results, $primary);
        if (empty($this->__currentUser)) {
            $user_id = Configure::read('CurrentUserId');
            $this->User = ClassRegistry::init('User');
            if ($user_id) {
                $this->__currentUser = $this->User->getAuthUser($user_id);
            }
        }
        foreach ($results as $i => $v) {
            if (!empty($v[$this->alias]['related_object_type']) && !empty($v[$this->alias]['related_object_uuid'])) {
                $results[$i][$this->alias]['related_object'] = $this->getRelatedElement($this->__currentUser, $v[$this->alias]['related_object_type'], $v[$this->alias]['related_object_uuid']);
            }
        }
        return $results;
    }

    public function getRelatedElement(array $user, $type, $uuid): array
    {
        $data = [];
        if ($type == 'Event') {
            $this->Event = ClassRegistry::init('Event');
            $params = [
            ];
            $data = $this->Event->fetchSimpleEvent($user, $uuid, $params);
        } else if ($type == 'Attribute') {
            $this->Attribute = ClassRegistry::init('Attribute');
            $params = [
                'conditions' => [
                    ['Attribute.uuid' => $uuid],
                ],
                'contain' => ['Event' => 'Orgc', 'Object',]
            ];
            $data = $this->Attribute->fetchAttributeSimple($user, $params);
            $data = $this->rearrangeData($data, 'Attribute');
        } else if ($type == 'Object') {
            $this->Object = ClassRegistry::init('MispObject');
            $params = [
                'conditions' => [
                    ['Object.uuid' => $uuid],
                ],
                'contain' => ['Event' => 'Orgc',]
            ];
            $data = $this->Object->fetchObjectSimple($user, $params);
            if (!empty($data)) {
                $data = $data[0];
            }
            $data = $this->rearrangeData($data, 'Object');
        } else if ($type == 'Note') {
            $this->Note = ClassRegistry::init('Note');
            $params = [

            ];
            $data = $this->Note->fetchNote();
        } else if ($type == 'Opinion') {
            $this->Opinion = ClassRegistry::init('Opinion');
            $params = [

            ];
            $data = $this->Opinion->fetchOpinion();
        } else if ($type == 'Relationship') {
            $this->Relationship = ClassRegistry::init('Relationship');
            $params = [

            ];
            $data = $this->Relationship->fetchRelationship();
        }
        return $data;
    }

    private function rearrangeData(array $data, $objectType): array
    {
        $models = ['Event', 'Attribute', 'Object', 'Organisation', ];
        if (!empty($data)) {
            foreach ($models as $model) {
                if ($model == $objectType) {
                    continue;
                }
                if (isset($data[$model])) {
                    $data[$objectType][$model] = $data[$model];
                    unset($data[$model]);
                }
            }
        }
        $data[$objectType]['Organisation'] = $data[$objectType]['Event']['Orgc'];
        $data[$objectType]['orgc_uuid'] = $data[$objectType]['Event']['Orgc']['uuid'];
        unset($data[$objectType]['Event']['Orgc']);
        return $data;
    }
}
