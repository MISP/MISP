<?php
App::uses('AppHelper', 'View/Helper');

    class UtilityHelper extends AppHelper {
        public function space2nbsp($string) {
            $string = str_replace("\t", "&nbsp&nbsp&nbsp&nbsp", $string);
            $string = preg_replace("/\s\s+/", "&nbsp;", $string);
            //$string = str_replace(' ', "&nbsp", $string);
            return $string;
        }
    }

