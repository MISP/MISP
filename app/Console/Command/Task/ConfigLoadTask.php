<?php
    class ConfigLoadTask extends Shell {
        public function execute() {
            Configure::load('config');
        }
    }
?>
