<?php
namespace App\View\Helper;

use Cake\View\Helper;

// This helper helps determining the brightness of a colour (initially only used for the tagging) in order to decide
// what text colour to use against the background (black or white)
class ACLHelper extends Helper {

    private $roleAccess = [];

    public function checkAccess($controller, $action) {
        if (empty($this->roleAccess)) {
            $this->roleAccess = $this->getView()->get('roleAccess');
        }
        if (
            in_array($action, $this->roleAccess['*']) ||
            (isset($this->roleAccess[$controller]) && in_array($action, $this->roleAccess[$controller]))
        ) {
            return true;
        } else {
            return false;
        }
    }
}
