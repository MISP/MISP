<?php
/*
 *  Simple form to fetch/submit for toggle endpoints
 *  Takes the current state and reverses it.
 *  It is expected to be POSTed to the same endpoint as used by the GET request
 *  to fetch it.
 *
 */
    echo $this->Form->create();
    echo $this->Form->input('value', array('default' => ($data ? 0 : 1)));
    echo $this->Form->end();
?>
