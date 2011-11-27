<?php
class Signature extends AppModel {
    var $name = 'Signature';
    var $order = array("Signature.event_id" => "DESC", "Signature.type" => "ASC");
    var $validate = array(
        'event_id' => array(
            'numeric' => array(
                'rule' => array('numeric'),
                //'message' => 'Your custom message here',
                //'allowEmpty' => false,
                'required' => true,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
        ),
        'type' => array(
            'allowedChoice' => array(
                'rule' => array('inList', array('md5','sha1',
                                                'filename',
                                                'ip-src',
                                                'ip-dst',
                                                'domain',
                                                'email-src',
                                                'email-dst',
                                                'email-subject',
                                                'email-attachment',
                                                'url',
                                                'user-agent',
                                                'regkey',
                                                'AS',
                                                'other')),
                'message' => 'Options : md5, sha1, filename, ip, domain, email, url, regkey, AS, other, ...'
            ),
        ),
        'value' => array(
            'notempty' => array(
                'rule' => array('notempty'),
                'message' => 'Please fill in this field',
                //'allowEmpty' => false,
                //'required' => false,
                //'last' => false, // Stop validation after this rule
                //'on' => 'create', // Limit validation to 'create' or 'update' operations
            ),
            'rightformat' => array(
                'rule' => array('validateSignatureValue'),
                'message' => 'Value not in the right type/format. Please double check the value or select "other" for a type.'
            ),
//            'unique' => array(
//                'rule' => array('signatureExists'),
//                'message' => 'Signature is already used in another event.' // Message set by signatureExists() function
//            )
        ),
    );
    //The Associations below have been created with all possible keys, those that are not needed can be removed

    var $belongsTo = array(
        'Event' => array(
            'className' => 'Event',
            'foreignKey' => 'event_id',
            'conditions' => '',
            'fields' => '',
            'order' => ''
        )
    );
    
    function signatureExists($fields) {
        $result = $this->find('first', array('conditions' => $fields, 'recursive' => -1));
        // signature doesn't exist
        if (empty($result)) return true;
        // signature exists
        return 'Signature is already used in <a href="/events/view/'.$result['Signature']['event_id'].'">this event</a>.'; // LATER find a way to do fill path automatically. // LATER permit user to a sig that exists.
    }

    function validateSignatureValue ($fields) {
        $value = $fields['value'];
        switch($this->data['Signature']['type']) {
            case 'md5':
                if (preg_match("#^[0-9a-f]{32}$#i", $value))
                    return true;
                return 'Checksum has invalid lenght or format. Please double check the value or select "other" for a type.';
                break;
            case 'sha1':
                if (preg_match("#^[0-9a-f]{40}$#i", $value))
                    return true;
                return 'Checksum has invalid lenght or format. Please double check the value or select "other" for a type.';
                break;
            case 'filename':
                // no newline
                if (!preg_match("#\n#", $value))
                    return true;
                break;
            case 'ip-src':
                $parts = explode("/", $value);
                // [0] = the ip
                // [1] = the network address 
                if (count($parts) <= 2 ) {
                    // ipv4 and ipv6 matching 
                    if (filter_var($parts[0],FILTER_VALIDATE_IP)) {
                        // ip is validated, now check if we have a valid network mask
                        if (empty($parts[1]))
                            return true;
                        else if(is_numeric($parts[1]) && $parts[1] < 129)   
                            return true;
                    }
                }
                return 'IP address has invalid format. Please double check the value or select "other" for a type.';
                break;
            case 'ip-dst':
                $parts = explode("/", $value);
                // [0] = the ip
                // [1] = the network address 
                if (count($parts) <= 2 ) {
                    // ipv4 and ipv6 matching 
                    if (filter_var($parts[0],FILTER_VALIDATE_IP)) {
                        // ip is validated, now check if we have a valid network mask
                        if (empty($parts[1]))
                            return true;
                        else if(is_numeric($parts[1]) && $parts[1] < 129)   
                            return true;
                    }
                }
                return 'IP address has invalid format. Please double check the value or select "other" for a type.';
                break;
            case 'domain':
                if(preg_match("#^[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value))
                    return true;
                return 'Domain name has invalid format. Please double check the value or select "other" for a type.';
                break;
            case 'email-src':
                // we don't use the native function to prevent issues with partial email addresses
                if(preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value))
                    return true;
                return 'Email address has invalid format. Please double check the value or select "other" for a type.';
                break;
            case 'email-dst':
                // we don't use the native function to prevent issues with partial email addresses
                if(preg_match("#^[A-Z0-9._%+-]*@[A-Z0-9.-]+\.[A-Z]{2,4}$#i", $value))
                    return true;
                return 'Email address has invalid format. Please double check the value or select "other" for a type.';
                break;
            case 'email-subject':
                // no newline
                if (!preg_match("#\n#", $value))
                    return true;
                break;
            case 'email-attachment':
                // no newline
                if (!preg_match("#\n#", $value))
                    return true;
                break;
            case 'url':
                // no newline
                if (!preg_match("#\n#", $value))
                    return true;
                break;
            case 'user-agent':
                // no newline
                if (!preg_match("#\n#", $value))
                    return true;
                break;
            case 'regkey':
                // no newline
                if (!preg_match("#\n#", $value))
                    return true;
                break;
            case 'other':
                return true;
                break;
        }

        // default action is to return false
        return false;

    }

    
//     function getRelatedEvents() {
//         // FIXME write this function    
//         $conditions = array('Signatures.value =' => $signature['value'], 'Signatures.type =' => $signature['type']);
//         $similar_signatures = $this->Signatures->find('all',array('conditions' => $conditions));
//         //debug($similar_signatures);
//         print $signature['value']."\t ";
//         foreach ($similar_signatures as $similar_signature) {
//             print $similar_signature['Signatures']['event_id']." ";
//         }
//     }

}
