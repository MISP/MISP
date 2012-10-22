<?php

class Populate023Shell extends AppShell {
    public $tasks = array('Groups', 'GroupToAroAco', 'GroupId');
    public function main() {
    	// perform tasks
    	sleep(30);
    	$this->Groups->execute();
        $this->GroupId->execute('2');
        $this->GroupToAroAco->execute();
    }
}