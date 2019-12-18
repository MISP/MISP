<?php
App::uses('AppHelper', 'View/Helper');

    // prepend user names on the header with some text based on the given rules
    class UserNameHelper extends AppHelper {

        public function prepend($email) {
            $lower_email = strtolower($email);
            if (
                (strpos($lower_email, 'saad') !== false && strpos($lower_email, 'thehive-project')) ||
                strpos($lower_email, 'saad.kadhi') !== false
            ) {
                return '<i class="fas fa-frown white"></i>&nbsp;';
            } else if (strpos($lower_email, 'enrico.lovat') !== false) {
                return '<i class="fas fa-horse-head white"></i>&nbsp;';
            } else if (strpos($lower_email, 'christophe.vandeplas') !== false) {
                return '<i class="fas fa-smile-beam white"></i>&nbsp;';
            } else if (strpos($lower_email, 'rand') !== false && (strpos($lower_email, 'ecrime') !== false)) {
                return '<i class="fas fa-camera white"></i>&nbsp;';
            }
            return '';
        }
    }
