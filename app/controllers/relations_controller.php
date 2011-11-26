<?php

class RelationsController extends AppController {

    var $name = 'Relations';

    function index() {
        $this->Relations->find('all');
        debug($this);
        
    }

//     /**
//      * Updates the relations table for a specific Signature
//      * @param unknown_type $id
//      */
//     function _updateForSignature($id) {
//     	// remove all entries in the relations table
//     		// remove all entries where signature_id
//     		// remove all entries where event_id
    	
//     	// search for similar signatures
    	

//     	// create new entries
//     }
    
    function _getRelationsForEvent($id) {
        // get relations_id from Relations for event_id
        
        // get event_id[] from Relations for relations_id
        
        // perhaps write a subquery ?
        
    }
    
}
