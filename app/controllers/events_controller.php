<?php

class EventsController extends AppController {

    var $name = 'Events';
    var $paginate = array(
        'limit' => 50,
        'order' => array(
            'Event.date' => 'DESC'
        )
    );
    var $components = array('Security', 'Email');

    function beforeFilter() {
        $this->Auth->allow('xml');
        $this->Auth->allow('snort');
        
        //$this->Security->requirePost('delete'); // FIXME do this for every controller and fix the urls in the pages
        
        // These variables are required for every view
        $me_user = $this->Auth->user();
        $this->set('me', $me_user['User']);
        $this->set('isAdmin', $this->isAdmin());
    }


    function index() {
        // list the events
        $this->Event->recursive = 0;
        $this->set('events', $this->paginate());
        
        if (empty($me_user['User']['gpgkey'])) {
            $this->Session->setFlash(__('No GPG key set in your profile. To receive emails, submit your public key in your profile.', true));
        }
    }

    function view($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid event', true));
            $this->redirect(array('action' => 'index'));
        }
        
        $this->set('relatedEvents', $this->_getRelatedEvents($id));
        $this->set('event', $this->Event->read(null, $id));
    }

    function add() {
        $user = $this->Auth->user();
        if (!empty($this->data)) {
            // force check userid and orgname if its from yourself
            $this->data['Event']['user_id'] = $user['User']['id'];
            $this->data['Event']['org'] = $user['User']['org'];
            $this->Event->create();
            if ($this->Event->save($this->data)) {
                $this->Session->setFlash(__('The event has been saved', true));
                $this->redirect(array('action' => 'view', $this->Event->getId()));
            } else {
                $this->Session->setFlash(__('The event could not be saved. Please, try again.', true));
            }
        }
        
        // combobox for risks
        $risks = $this->Event->validate['risk']['allowedChoice']['rule'][1];
        $risks = $this->arrayToValuesIndexArray($risks);
        $this->set('risks',compact('risks'));
    }

    function edit($id = null) {
        if (!$id && empty($this->data)) {
            $this->Session->setFlash(__('Invalid event', true));
            $this->redirect(array('action' => 'index'));
        }
        // only edit own events
        $user = $this->Auth->user();
        $old_event = $this->Event->read(null, $id);
        if (!$this->isAdmin() && $user['User']['org'] != $old_event['Event']['org']) {
            $this->Session->setFlash(__('You can only edit events from your organisation.', true));
            $this->redirect(array('action' => 'view', $id));
        }
        // form submit
        if (!empty($this->data)) {
            // always force the user and org, but do not force it for admins
            if (!$this->isAdmin()) {
                $this->data['Event']['user_id'] = $user['User']['id'];
                $this->data['Event']['org'] = $user['User']['org'];
            }
            // we probably also want to remove the alerted flag
            $this->data['Event']['alerted'] = 0;
        
            if ($this->Event->save($this->data)) {
                // redirect
                $this->Session->setFlash(__('The event has been saved', true));
                $this->redirect(array('action' => 'view', $id));
            } else {
                $this->Session->setFlash(__('The event could not be saved. Please, try again.', true));
            }
        }
        // no form submit
        if (empty($this->data)) {
            $this->data = $this->Event->read(null, $id);
        }
        
        // combobox for types
        $risks = $this->Event->validate['risk']['allowedChoice']['rule'][1];
        $risks = $this->arrayToValuesIndexArray($risks);
        $this->set('risks',compact('risks'));
    }

    function delete($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for event', true));
            $this->redirect(array('action'=>'index'));
        }
        // only delete own events
        $user = $this->Auth->user();
        $old_event = $this->Event->read(null, $id);
        if (!$this->isAdmin() && $user['User']['org'] != $old_event['Event']['org']) {
            $this->Session->setFlash(__('You can only delete events from your organisation.', true));
            $this->redirect(array('action' => 'view', $id));
        }
        // delete event or throw error
        if ($this->Event->delete($id)) {
            $this->Session->setFlash(__('Event deleted', true));
            $this->redirect(array('action'=>'index'));
        }
        $this->Session->setFlash(__('Event was not deleted', true));
        $this->redirect(array('action' => 'index'));
    }


    /**
     * Send out an alert email to all the users that wanted to be notified.
     * Users with a GPG key will get the mail encrypted, other users will get the mail unencrypted
     */
    function alert($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for event', true));
            $this->redirect(array('action'=>'index'));
        }
        // only allow alert for own events or admins
        $user = $this->Auth->user();
        $old_event = $this->Event->read(null, $id);
        if (!$this->isAdmin() && $user['User']['org'] != $old_event['Event']['org']) {
            $this->Session->setFlash(__('You can only send alerts for events from your organisation.', true));
            $this->redirect(array('action' => 'view', $id));
        }
        
        // fetch the event and build the body
        $event = $this->Event->read(null, $id);
        if (1 == $event['Event']['alerted']) {
            $this->Session->setFlash(__('Everyone has already been alerted for this event. To alert again, first edit this event.', true));
            $this->redirect(array('action' => 'view', $id));
        }
        $relatedEvents = $this->_getRelatedEvents($id);
        
        $body = "";
        $appendlen = 20;
        $body  = 'URL         : '.Configure::read('CyDefSIG.baseurl').'/events/view/'.$event['Event']['id']."\n";
        $body .= 'Event       : '.$event['Event']['id']."\n";
        $body .= 'Date        : '.$event['Event']['date']."\n";
        $body .= 'Reported by : '.Sanitize::html($event['Event']['org'])."\n";
        $body .= 'Risk        : '.$event['Event']['risk']."\n";
        if (!empty($relatedEvents)) {
            foreach ($relatedEvents as $relatedEvent){
                $body .= 'Related to  : '.$relatedEvent['Event']['id'].' ('.$relatedEvent['Event']['date'].')'."\n" ;
            
            }
        }
        $body .= "\n";
        $body .= 'Signatures  :'."\n";
        if (!empty($event['Signature'])) {
            foreach ($event['Signature'] as $signature){
                $body .= '- '.$signature['type'].str_repeat(' ', $appendlen - 2 - strlen( $signature['type'])).': '.Sanitize::html($signature['value'])."\n"; 
            }
        }
        $body .= "\n";
        $body .= 'Extra info  : '."\n";
        $body .= Sanitize::html($event['Event']['info']);
        
        // sign the body
        require_once 'Crypt/GPG.php';
        $gpg = new Crypt_GPG();
        $gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
        $body_signed = $gpg->sign($body, Crypt_GPG::SIGN_MODE_CLEAR);
        
        
        $this->loadModel('Users');
        
        //
        // Build a list of the recipients that get a non-encrypted mail
        // But only do this it if it is allowed in the bootstrap.php file.
        //
        if ('false' == Configure::read('GnuPG.onlyencrypted')) {
            $alert_users = $this->Users->find('all', array(
                'conditions' => array('Users.autoalert' => 1,
                                      'Users.gpgkey =' => ""),
                'recursive' => 0,
                ) );
            $alert_emails = Array();
            foreach ($alert_users as $user) {
                $alert_emails[] = $user['Users']['email'];
            }
            // prepare the the unencrypted email
            $this->Email->from = "CyDefSIG <sig@cyber-defence.be>";
            $this->Email->to = "CyDefSIG <sig@cyber-defence.be>";
            $this->Email->return = "sig@cyber-defence.be";
            $this->Email->bcc = $alert_emails; 
            $this->Email->subject = "[CyDefSIG] Event ".$id." - ".$event['Event']['risk']." - TLP Amber";
            //$this->Email->delivery = 'debug';   // do not really send out mails, only display it on the screen
            $this->Email->template = 'body';
            $this->Email->sendAs = 'text';        // both text or html 
            $this->set('body', $body_signed);        
            // send it
            $this->Email->send();
            // If you wish to send multiple emails using a loop, you'll need 
            // to reset the email fields using the reset method of the Email component. 
            $this->Email->reset();
        }
        
        //
        // Build a list of the recipients that wish to receive encrypted mails. 
        //
        $alert_users = $this->Users->find('all', array(
            'conditions' => array('Users.autoalert' => 1,
                                  'Users.gpgkey !=' => ""),
            'recursive' => 0,
            ) );
        // encrypt the mail for each user and send it separately
        foreach ($alert_users as $user) {
            // send the email
            $this->Email->from = "CyDefSIG <sig@cyber-defence.be>";
            $this->Email->to = "<".$user['Users']['email'].">";
            $this->Email->return = "sig@cyber-defence.be";
            $this->Email->subject = "[CyDefSIG] Event ".$id." - ".$event['Event']['risk'];
            //$this->Email->delivery = 'debug';   // do not really send out mails, only display it on the screen
            $this->Email->template = 'body';
            $this->Email->sendAs = 'text';        // both text or html 
            
            // import the key of the user into the keyring // LATER do that when the user uploads a new key, but don't forget to remove the old keys before
            $key_import_output = $gpg->importKey($user['Users']['gpgkey']);
            // say what key should be used to encrypt
            $gpg = new Crypt_GPG();
            //$gpg->addEncryptKey($user['Users']['email']);
            $gpg->addEncryptKey($key_import_output['fingerprint']); // use the key that was given in the import

            $body_enc_sig = $gpg->encrypt($body_signed, true);
            
            $this->set('body', $body_enc_sig);        
            //debug($body_enc_sig);
            $this->Email->send();
            // If you wish to send multiple emails using a loop, you'll need 
            // to reset the email fields using the reset method of the Email component. 
            $this->Email->reset();
        }    

        
        
        // update the DB to set the alerted flag
        $this->Event->set('alerted', 1);
        $this->Event->save();
        
        // redirect to the view event page
        $this->Session->setFlash(__('Email sent to all participants.', true));
        $this->redirect(array('action' => 'view', $id));
    }
    
    
    /**
     * Send out an contact email to the person who posted the event.
     * Users with a GPG key will get the mail encrypted, other users will get the mail unencrypted
     * @todo allow the user to enter a comment in the contact email.
     */
    function contact($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for event', true));
            $this->redirect(array('action'=>'index'));
        }
        
        // fetch the event
        $event = $this->Event->read(null, $id);
        $reporter = $event['User']; // email, gpgkey
        
        $me_user = $this->Auth->user();
        $me_user = $me_user['User']; // email, gpgkey
        
        $body = "";
        $body .="Hello, \n";
        $body .="\n";
        $body .="Someone wants to get in touch with you concerning a CyDefSIG event. \n";
        $body .="\n";
        $body .="You can reach him at ".$me_user['email']."\n";
        if (!empty($me_user['gpgkey']))
            $body .="His GPG/PGP key is added as attachment to this email. \n";
        $body .="\n";
        $body .="The event is the following: \n";
        
        // print the event in mail-format
        // LATER place event-to-email-layout in a function
        $appendlen = 20;
        $body .= 'Event       : '.$event['Event']['id']."\n";
        $body .= 'Date        : '.$event['Event']['date']."\n";
        $body .= 'Reported by : '.Sanitize::html($event['Event']['org'])."\n";
        $body .= 'Risk        : '.$event['Event']['risk']."\n";
        $body .= 'Signatures  :'."\n";
        if (!empty($event['Signature'])) {
            $i = 0;
            foreach ($event['Signature'] as $signature){
                $body .= '        - '.$signature['type'].str_repeat(' ', $appendlen - 2 - strlen( $signature['type'])).': '.Sanitize::html($signature['value'])."\n"; 
            }
        }    
        $body .= 'Extra info  : '."\n";
        $body .= Sanitize::html($event['Event']['info']);
        
        // sign the body
        require_once 'Crypt/GPG.php';
        $gpg = new Crypt_GPG();
        $gpg->addSignKey(Configure::read('GnuPG.email'), Configure::read('GnuPG.password'));
        $body_signed = $gpg->sign($body, Crypt_GPG::SIGN_MODE_CLEAR);
        
        if (!empty($reporter['gpgkey'])) {
            // import the key of the user into the keyring
            // this isn't really necessary, but it gives it the fingerprint necessary for the next step
            $key_import_output = $gpg->importKey($reporter['gpgkey']);
            // say what key should be used to encrypt
            $gpg = new Crypt_GPG();
            $gpg->addEncryptKey($key_import_output['fingerprint']); // use the key that was given in the import

            $body_enc_sig = $gpg->encrypt($body_signed, true);
        } else {
            $body_enc_sig = $body_signed;
            // FIXME should I allow sending unencrypted "contact" mails to people if they didn't import they GPG key? 
        }
        
        // prepare the email
        $this->Email->from = "CyDefSIG <sig@cyber-defence.be>";
        $this->Email->to = "<".$reporter['email'].">";
        $this->Email->subject = "[CyDefSIG] Need info about event ".$id." - TLP Amber";
        //$this->Email->delivery = 'debug';   // do not really send out mails, only display it on the screen
        $this->Email->template = 'body';
        $this->Email->sendAs = 'text';        // both text or html 
        $this->set('body', $body_enc_sig);        
        
        // Add the GPG key of the user as attachment 
        // LATER sign the attached GPG key
        if (!empty($me_user['gpgkey'])) {
            // save the gpg key to a temporary file
            $tmpfname = tempnam(TMP, "GPGkey");
            $handle = fopen($tmpfname, "w");
            fwrite($handle, $me_user['gpgkey']);
            fclose($handle);
            // attach it 
            $this->Email->attachments = array(
                'gpgkey.asc' => $tmpfname
            );
        }
        
        // send it
        $this->Email->send();
        
        // remove the temporary gpg file
        if (!empty($me_user['gpgkey']))
            unlink($tmpfname);
        
        // redirect to the view event page
        $this->Session->setFlash(__('Email sent to the reporter.', true));
        $this->redirect(array('action' => 'view', $id));
        
    }

    
    function export() {
        // Simply display a static view
    }
    
    
    function xml($key) {
        // check if the key is valid -> search for users based on key
        $this->loadModel('Users');
        // no input sanitization necessary, it's done by model
        $user = $this->Users->findByAuthkey($key);
        if (empty($user))
            $this->cakeError('error403', array('message' => 'Incorrect authentication key'));
        // display the full xml
        $this->header('Content-Type: text/xml');    // set the content type
        $this->layout = 'xml/xml';
        $this->set('events', $this->Event->findAllByAlerted(1)); // find events that are finished
    }
    
    function snort($key) {
        // check if the key is valid -> search for users based on key
        $this->loadModel('Users');
        $this->loadModel('Signatures');
        // no input sanitization necessary, it's done by model
        $user = $this->Users->findByAuthkey($key);
        if (empty($user))
            $this->cakeError('error403', array('message' => 'Incorrect authentication key'));
        // display the full snort rulebase
        $this->layout = 'xml/xml'; // LATER better layout than xml
        
        $rules= array();
        
        // find events that are finished
        $events = $this->Event->findAllByAlerted(1); 
        
        
        foreach ($events as $event) {
            # proto src_ip src_port direction dst_ip dst_port msg rule_content tag sid rev 
            $rule_format = 'alert %s %s %s %s %s %s (msg: "CyDefSIG %s, Event '.$event['Event']['id'].', '.$event['Event']['risk'].'"; %s %s classtype:targeted-attack; sid:%d; rev:%d; reference:url,'.Configure::read('CyDefSIG.baseurl').'/events/'.$event['Event']['id'].';) ';
        
            $sid = 3000000+($event['Event']['id']*100); // LATER this will cause issues with events containing more than 99 signatures
            //debug($event);
            foreach ($event['Signature'] as $signature) {
                $sid++;
                switch ($signature['type']) {
                    // LATER test all the snort signatures
                    // LATER add the tag keyword in the rules to capture network traffic
                    // LATER sanitize every $signature['value'] to not conflict with snort
                    case 'ip-dst':
                        $rules[] = sprintf($rule_format, 
                            'ip',                           // proto
                            '$HOME_NET',                    // src_ip
                            'any',                          // src_port
                            '->',                           // direction
                            $signature['value'],            // dst_ip
                            'any',                          // dst_port
                            'Outgoing To Bad IP '.$signature['value'],        // msg
                            '',                             // rule_content
                            '',                             // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        break;
                    case 'ip-src':
                        $rules[] = sprintf($rule_format, 
                            'ip',                           // proto
                            $signature['value'],            // src_ip
                            'any',                          // src_port
                            '->',                           // direction
                            '$HOME_NET',                    // dst_ip
                            'any',                          // dst_port
                            'Incoming From Bad IP '.$signature['value'],        // msg
                            '',                             // rule_content
                            '',                             // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        break;
                    case 'email-src':
                        $rules[] = sprintf($rule_format, 
                            'tcp',                          // proto
                            '$EXTERNAL_NET',                // src_ip
                            'any',                          // src_port
                            '<>',                           // direction
                            '$SMTP_SERVERS',                // dst_ip
                            '25',                           // dst_port
                            'Bad Source Email Address '.$signature['value'],        // msg
                            'flow:established,to_server; content:"MAIL FROM|3a|"; nocase; content:"'.$signature['value'].'"; nocase;',  // rule_content
                            'tag:session,600,seconds;',     // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        break;
                    case 'email-dst':
                        $rules[] = sprintf($rule_format, 
                            'tcp',                          // proto
                            '$EXTERNAL_NET',                // src_ip
                            'any',                          // src_port
                            '<>',                           // direction
                            '$SMTP_SERVERS',                // dst_ip
                            '25',                           // dst_port
                            'Bad Destination Email Address '.$signature['value'],        // msg
                            'flow:established,to_server; content:"RCPT TO|3a|"; nocase; content:"'.$signature['value'].'"; nocase;',  // rule_content
                        	'tag:session,600,seconds;',     // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        break;
                    case 'email-subject':
                        // LATER email-subject rule might not match because of line-wrapping
                    	$rules[] = sprintf($rule_format, 
                            'tcp',                          // proto
                            '$EXTERNAL_NET',                // src_ip
                            'any',                          // src_port
                            '<>',                           // direction
                            '$SMTP_SERVERS',                // dst_ip
                            '25',                           // dst_port
                            'Bad Email Subject '.$signature['value'],        // msg
                            'flow:established,to_server; content:"Subject|3a|"; nocase; content:"'.$signature['value'].'"; nocase;',  // rule_content
                    		'tag:session,600,seconds;',     // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        break;
                    case 'email-attachment':
                        // LATER email-attachment rule might not match because of line-wrapping
                    	$rules[] = sprintf($rule_format, 
                            'tcp',                          // proto
                            '$EXTERNAL_NET',                // src_ip
                            'any',                          // src_port
                            '<>',                           // direction
                            '$SMTP_SERVERS',                // dst_ip
                            '25',                           // dst_port
                            'Bad Email Attachment '.$signature['value'],        // msg
                            'flow:established,to_server; content:"Content-Disposition: attachment|3b| filename=|22|"; content:"'.$signature['value'].'|22|";',  // rule_content   // LATER test and finetune this snort rule https://secure.wikimedia.org/wikipedia/en/wiki/MIME#Content-Disposition
                    		'tag:session,600,seconds;',     // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        break;
                    case 'domain':
                        $rules[] = sprintf($rule_format, 
                            'udp',                          // proto
                            'any',                          // src_ip
                            'any',                          // src_port
                            '->',                           // direction
                            'any',                          // dst_ip
                            '53',                           // dst_port
                            'Lookup Of Bad Domain '.$signature['value'],        // msg
                            'content:"'.$signature['value'].'"; nocase;',  // rule_content
                        	'',                             // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        $sid++;
                        $rules[] = sprintf($rule_format, 
                            'tcp',                          // proto
                            'any',                          // src_ip
                            'any',                          // src_port
                            '->',                           // direction
                            'any',                          // dst_ip
                            '53',                           // dst_port
                            'Lookup Of Bad Domain '.$signature['value'],        // msg
                            'content:"'.$signature['value'].'"; nocase;',  // rule_content
                        	'',                             // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        $sid++;
                        //break; // domain should also detect the domain name in a url
                    case 'url':
                        $rules[] = sprintf($rule_format, 
                            'tcp',                          // proto
                            '$HOME_NET',                    // src_ip
                            'any',                          // src_port
                            '->',                           // direction
                            '$EXTERNAL_NET',                // dst_ip
                            '$HTTP_PORTS',                  // dst_port
                            'Outgoing Bad HTTP URL '.$signature['value'],        // msg
                            'flow:to_server,established; uricontent:"'.$signature['value'].'"; nocase;',  // rule_content
                        	'tag:session,600,seconds;',     // tag
                            $sid,                           // sid
                            1                               // rev
                            );
                        break;
                    case 'user-agent':
                        $rules[] = "";
                        // TODO write snort user-agent rule
                        break;
                    default:
                        break;
                }

            }
            
        }
        print ("#<h1>This part is not finished and might be buggy. Please report any issues.</h1>\n");
        
        print "#<pre> \n";
        foreach ($rules as $rule)
        print $rule."\n";
        print "#</pre>\n";
        
        $this->set('rules', $rules);
        
    }

    
    /**
     * 
     * Return an array of related event_ids
     * @param int $eventid
     * @return multitype:string Array containing the related event_ids
     * @todo move _getRelatedEvents($eventid) in the Event and Signature model. Make 2 versions. 1/ related events 2/ related signatures
     * @todo refactor this concept to a more performant system. Now the performance will decrease exponentially with the number of signatures
     */
    function _getRelatedEvents($id) {
        // first get a list of related event_ids
        // then do a single query to search for all the events with that id 
        $relatedEventIds = Array();
        $this->loadModel('Signature');
        
        $event = $this->Event->read(null, $id);
        foreach ($event['Signature'] as $signature ) {
            if ($signature['type'] == 'other')
                continue;  // sigs of type 'other' should not be matched against the others
            $conditions = array('Signature.value =' => $signature['value'], 'Signature.type =' => $signature['type']);
            $similar_signatures = $this->Signature->find('all',array('conditions' => $conditions));
            foreach ($similar_signatures as $similar_signature) {
                if ($id == $similar_signature['Signature']['event_id']) 
                    continue; // same as this event, not needed in the list
                
                $relatedEventIds[] = $similar_signature['Signature']['event_id'];
                
            }
        }
        $conditions = array("Event.id" => $relatedEventIds);
        $relatedEvents= $this->Event->find('all', 
                                           array('conditions' => $conditions, 
                                                 'recursive' => 0,
                                                 'order' => 'Event.date DESC',
                                                 'fields' => 'Event.*'
                                                 )
                                           );
        return $relatedEvents;
    }
    
}
