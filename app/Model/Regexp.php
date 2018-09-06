<?php

App::uses('AppModel', 'Model');

/**
 * Regexp Model
 *
 */
class Regexp extends AppModel
{
    public $actsAs = array(
            'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
                    'roleModel' => 'Role',
                    'roleKey' => 'role_id',
                    'change' => 'full'
            ),
    );

    public $validate = array(
            'regexp' => array(
                    'rule'    => 'checkRegexp',
                    'message' => 'This is not a valid regular expression. Don\'t forget the delimiters!'
            )
    );

    public $useTable = 'regexp';

    public function beforeValidate($options = array())
    {
        $this->sanitizeModifiers($this->data['Regexp']['regexp']);
    }

    public function sanitizeModifiers(&$regex)
    {
        preg_match('/[a-zA-Z]*$/i', $regex, $modifiers);
        if (!empty($modifiers[0])) {
            $modifier_length = strlen($modifiers[0]);
            $regex = substr($regex, 0, -$modifier_length);
            $modifiers[0] = str_ireplace('e', '', $modifiers[0]);
            $regex .= $modifiers[0];
        }
    }

    public function checkRegexp()
    {
        if (@preg_replace($this->data['Regexp']['regexp'], 'success', $this->data['Regexp']['regexp']) != null) {
            return true;
        }
        return false;
    }

    // find all the similar Regular expressions and return them. If $delete is true, delete them instead of returning them.
    public function find_similar($id, $delete = false)
    {
        $allRegexp = $this->find('all');
        $original = null;
        $finalArray = array();
        // Let's find and read the original so we know what to look for:
        foreach ($allRegexp as $k => $v) {
            if ($v['Regexp']['id'] == $id) {
                $original = $v;
            }
        }
        // if we found the original, let's try to find all of the regexp values that match the original in the regexp and replacement fields.
        // We should get a list of all the IDs (and their respective types) of regular expression entries that are duplicates created for various types.
        // ip-src /127.0.0.1/ -> '' and ip-dst /127.0.0.1/ -> '' (entries that blacklists the ip-source and ip-destination addresses 127.0.0.1) will be returned when editing
        // ip-src /127.0.0.1/ -> '', but other /127.0.0.1/ -> 'localhost' will not
        if ($original != null) {
            foreach ($allRegexp as $k => $v) {
                if ($original['Regexp']['regexp'] === $v['Regexp']['regexp'] && $original['Regexp']['replacement'] === $v['Regexp']['replacement']) {
                    if ($delete) {
                        // if the delete parameter is set to true, delete the regular expression. This is used for edits
                        $this->delete($v['Regexp']['id']);
                    } else {
                        $finalArray[] = array($v['Regexp']['id'], $v['Regexp']['type']);
                    }
                }
            }
        }
        return $finalArray;
    }

    public function replaceSpecific($string, $allRegexp = null, $type)
    {
        $orig = $string;
        foreach ($allRegexp as $regexp) {
            if (strlen($regexp['Regexp']['replacement']) && strlen($regexp['Regexp']['regexp']) && ($regexp['Regexp']['type'] === 'ALL' || $regexp['Regexp']['type'] === $type)) {
                $string = preg_replace($regexp['Regexp']['regexp'], $regexp['Regexp']['replacement'], $string);
            }
            if (!strlen($regexp['Regexp']['replacement']) && preg_match($regexp['Regexp']['regexp'], $string) && ($regexp['Regexp']['type'] === 'ALL' || $regexp['Regexp']['type'] === $type)) {
                return 0;
            }
        }
        if ($orig === $string) {
            return 2;
        }
        return 1;
    }
}
