<?php

namespace App\View\Helper;

use Cake\View\Helper\PaginatorHelper;

class LightPaginatorHelper extends PaginatorHelper
{
    public function numbers(array $options = []): string
    {
        return '';
    }

    public function counter(string $format = 'pages', array $options = []): string
    {
        return '';
    }

    public function last($last = 'last >>', array $options = []): string
    {
        return '';
    }

    public function hasNext(?string $model = null): bool
    {
        $model = $options['model'] ?? null;
        $params = $this->params($model);
        return $params['current'] >= $params['limit'];
    }
}
