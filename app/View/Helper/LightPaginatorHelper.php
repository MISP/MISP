<?php
App::uses('PaginatorHelper', 'View/Helper');

class LightPaginatorHelper extends PaginatorHelper
{
    public function numbers($options = array())
    {
        return '';
    }

    public function counter($options = array())
    {
        return '';
    }

    public function last($last = 'last >>', $options = array())
    {
        return '';
    }

    public function hasNext($model = null)
    {
        $model = $this->defaultModel();
        return $this->request->params['paging'][$model]['current'] >= $this->request->params['paging'][$model]['limit'];
    }
}
