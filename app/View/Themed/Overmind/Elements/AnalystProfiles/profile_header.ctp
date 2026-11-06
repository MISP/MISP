<?php
/**
 * The page header of a profile's view and editor: its name, the identity
 * and date pills, and one line of text. The owner and the shipped version
 * are in the rail's About card, where they carry their labels.
 *
 * @var array $profile
 * @var string|null $lead The line of text; the profile's own description
 *                        when absent
 */
if (isset($lead)) {
    $line = $lead;
} else {
    $line = trim(preg_replace('/\s+/u', ' ', (string)$profile['description']));
    if (preg_match('/^(.{320})./u', $line, $m)) {
        $line = $m[1];
        $cut = strrpos($line, ' ');
        if ($cut !== false && $cut > 160) {
            $line = substr($line, 0, $cut);
        }
        $line = rtrim($line, " ,;:") . '…';
    }
}

$this->set('headerTitle', $profile['name']);
$this->set('headerIdentity', $profile);
$this->set('headerTimestamps', $profile);
// `headerSection` prints the description raw.
$this->set('headerDescription', h($line));
