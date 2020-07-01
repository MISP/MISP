<?php

class MispSystemResourceWidget
{
    public $title = 'MISP System Resource Usage';
    public $render = 'SimpleList';
    public $width = 3;
    public $height = 3;
    public $params = array(
        'treshold' => 'Treshold for disk space'
    );
    public $description = 'Basic widget showing some system server statistics.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 30;
    public $placeholder =
    '{
        "treshold": "85"
    }';

	public function handler($user, $options = array())
	{

        $drive = round((1 - disk_free_space(getcwd())/disk_total_space(getcwd()))*100,2);
        $driveFree = $drive . "%";
        $driveFreeClass = "";
        if ($drive > intval($options['treshold'])) {
            $driveFree = $drive . "% - [Above Treshhold]";
            $driveFreeClass = "red";
        }

        $sysload = sys_getloadavg();

        preg_match('#MemFree:[\s\t]+([\d]+)\s+kB#', file_get_contents('/proc/meminfo'), $matches);
        $memoryFree = $matches[1];
        preg_match('#MemTotal:[\s\t]+([\d]+)\s+kB#', file_get_contents('/proc/meminfo'), $matches);
        $memoryTotal = $matches[1];

        $data = array(
                array( 'title' => __('User'), 'value' => $user['email']),
                array( 'title' => __('System'), 'value' => php_uname()),
                array( 'title' => __('Disk usage'), 'value' => h($driveFree), 'class' => $driveFreeClass),
                array( 'title' => __('Load'), 'value' => h($sysload[0] . " - " . $sysload[1] . " - " . $sysload[2])),
                array( 'title' => __('Memory'), 'value' => h(round($memoryFree/1024,2) . "M free (" . round((1 - $memoryFree/$memoryTotal)*100,2) . "% used)")),
                );
        return $data;
	}

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }
}
