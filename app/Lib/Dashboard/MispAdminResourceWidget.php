<?php

class MispAdminResourceWidget
{
    public $title = 'MISP Resource Usage';
    public $category = 'system';
    public $render = 'SimpleList';
    public $width = 2;
    public $height = 2;
    public $params = array();
    public $schema = array();
    public $description = 'Basic widget showing some server statistics in regards to MISP.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 3;


	public function handler($user, $options = array())
	{
        $this->Server = ClassRegistry::init('Server');
        $data = array();

        $redisInfo = $this->Server->redisInfo();
        if ($redisInfo['connection']) {
            $memory_stats = round($redisInfo['used_memory'] / 1024 / 1024) . 'M';
            $data[] = array(
                'title' => __('Current Redis memory usage'),
                'value' => h($memory_stats)
            );
            $memory_stats = round($redisInfo['used_memory_peak'] / 1024 / 1024) . 'M';
            $data[] = array(
                'title' => __('Peak Redis memory usage'),
                'value' => h($memory_stats)
            );
        }
        $db_bytes = 0;
        foreach ($this->Server->getSchemaInspector()->tableSizes() as $size) {
            $db_bytes += $size['total_in_bytes'];
        }
        $db_size = round($db_bytes / 1024 / 1024, 1);
        $data[] = array(
            'title' => __('MySQL DB disk usage'),
            'value' => h($db_size) . 'M'
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
