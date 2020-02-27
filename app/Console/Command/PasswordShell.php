<?php
/*
 * Reset a password
 *
 * arg0 = email
 * arg1 = new password
 */
class PasswordShell extends AppShell {

    public $uses = array('User');

    public function main()
    {
        $this->ConfigLoad->execute();
        if (!isset($this->args[0]) || empty($this->args[0]) || !isset($this->args[1]) || empty($this->args[1])) echo 'MISP password reset command line tool.' . PHP_EOL . 'To assign a new password for a user:' . PHP_EOL . APP . 'Console/cake Password [email] [password]' . PHP_EOL;
        else {
            // get the users that need their password hashed
            $results = $this->User->find('first', array('conditions' => array('email' => $this->args[0]), 'recursive' => -1));
            if (empty($results)) {
                echo 'User not found. Make sure you use the correct syntax: /var/www/MISP/app/Console/cake Password [email] [password]' . PHP_EOL;
                exit;
            }
            $results['User']['password'] = $this->args[1];
            $results['User']['confirm_password'] = $this->args[1];
            $change_pw = 1;
            if (!empty($this->params['override_password_change'])) {
                $change_pw = 0;
            }
            $results['User']['change_pw'] = $change_pw;
            if (!$this->User->save($results)) {
                echo 'Could not update account for User.id = ', $results['User']['id'], PHP_EOL;
                echo json_encode($this->User->validationErrors) . PHP_EOL;
                $this->out(print_r($this->User->invalidFields(), true));
            }
            echo 'Updated ', PHP_EOL;
        }
        exit;
    }

    public function getOptionParser()
    {
        $this->ConfigLoad->execute();
        $parser = parent::getOptionParser();
        $parser->addOption('override_password_change', array(
            'short' => 'o',
            'help' => __('override password change'),
            'boolean' => 1
        ));
        return $parser;
    }
}
