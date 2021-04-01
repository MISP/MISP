<?php
App::uses('AppModel', 'Model');
class EventGraph extends AppModel
{
    public $useTable = 'event_graph';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $belongsTo = array(
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
            'conditions' => '',
            'fields' => '',
            'order' => ''
        ),
        'User' => array(
            'className' => 'User',
            'foreignKey' => 'user_id',
            'conditions' => '',
            'fields' => '',
            'order' => ''
        )
    );


    public $validate = array(
        'network_json' => array(
            'rule' => array('isValidJson'),
            'message' => 'The provided eventGraph is not a valid json format',
            'required' => true,
        ),
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        $date = new DateTime();
        $this->data['EventGraph']['timestamp'] = $date->getTimestamp();
        return true;
    }

    public function isValidJson($fields)
    {
        $text = $fields['network_json'];
        $check = json_decode($text);
        if ($check === null) {
            return false;
        }
        return true;
    }

    public function getPictureData($eventGraph)
    {
        $b64 = str_replace('data:image/png;base64,', '', $eventGraph['EventGraph']['preview_img']);
        $imageDecoded = base64_decode($b64);
        $source = imagecreatefromstring($imageDecoded);
        imagesavealpha($source, true);
        ob_start();
        imagepng($source, null, 9);
        $imageData = ob_get_contents();
        ob_end_clean();
        imagedestroy($source);
        return $imageData;
    }
}
