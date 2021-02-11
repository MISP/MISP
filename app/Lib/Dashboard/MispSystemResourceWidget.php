<?php

class MispSystemResourceWidget
{
    public $title = 'MISP System Resource Usage';
    public $render = 'SimpleList';
    public $width = 3;
    public $height = 3;
    public $params = array(
        'threshold' => 'Threshold for disk space'
    );
    public $description = 'Basic widget showing some system server statistics.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 30;
    public $placeholder =
    '{
        "threshold": "85"
    }';

	public function handler(array $user, $options = array())
	{
	    // Keep BC with typo value
        $threshold = isset($options['threshold']) ? $options['threshold'] : (isset($options['treshold']) ? $options['treshold'] : 85);

        $cwd = getcwd();
        $drive = round((1 - disk_free_space($cwd)/disk_total_space($cwd))*100,2);
        $driveFree = $drive . "%";
        $driveFreeClass = "";
        if ($drive > intval($threshold)) {
            $driveFree = $drive . "% - [Above Threshold]";
            $driveFreeClass = "red";
        }

        $meminfo = file_get_contents('/proc/meminfo');
        preg_match('#MemFree:[\s\t]+([\d]+)\s+kB#', $meminfo, $matches);
        $memoryFree = $matches[1];
        preg_match('#MemTotal:[\s\t]+([\d]+)\s+kB#', $meminfo, $matches);
        $memoryTotal = $matches[1];

        $data = array(
            array( 'title' => __('User'), 'value' => $user['email']),
            array( 'title' => __('System'), 'value' => php_uname()),
            array( 'title' => __('Disk usage'), 'value' => h($driveFree), 'class' => $driveFreeClass),
            array( 'title' => __('Load'), 'value' => h(implode(" - ", sys_getloadavg()))),
            array( 'title' => __('Memory'), 'value' => h(round($memoryFree / 1024,2) . " MB free (" . round((1 - $memoryFree/$memoryTotal)*100,2) . " % used)")),
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
