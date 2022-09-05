<?php

class MispAdminResourceWidget
{
    public $title = 'MISP Resource Usage';
    public $render = 'SimpleList';
    public $width = 2;
    public $height = 2;
    public $params = array();
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
        $db_size = $this->Server->query(
            sprintf(
                "SELECT table_schema, ROUND(SUM(data_length + index_length) / 1024 / 1024, 1) AS 'size_mb' FROM information_schema.tables WHERE table_schema = '%s' GROUP BY table_schema;",
                $this->Server->getDataSource()->config['database']
            )
        )[0][0]['size_mb'];
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
