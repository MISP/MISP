<?php

class Relation extends AppModel {
    var $name = 'Relation';
    var $validate = array(
        'signature_id' => array(
            'notempty' => array(
                'rule' => array('notempty'),
            ),
        ),
        'event_id' => array(
            'notempty' => array(
                'rule' => array('notempty'),
            ),
        ),
        'relation_id' => array(
            'notempty' => array(
                'rule' => array('notempty'),
            ),
        ),
    );
    
    // We explicitly have no relations
    var $belongsTo = array(
        
    );

    var $hasMany = array(
        
    );


}
