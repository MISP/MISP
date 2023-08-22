<?php

namespace App\Controller\Component;

use Cake\Collection\Collection;
use Cake\Controller\Component;

class APIRearrangeComponent extends Component
{
    public function rearrangeForAPI(object $data, bool $wrap=false)
    {
        return $wrap ? ['response' => $this->rearrange($data)] : $this->rearrange($data);
    }

    protected function rearrange(object $data)
    {
        if (is_subclass_of($data, 'Iterator')) {
            $newData = [];
            $data->each(
                function ($value, $key) use (&$newData) {
                $value->rearrangeForAPI();
                $newData[] = $value;
                }
            );
            return new Collection($newData);
        } else {
            $data->rearrangeForAPI();
        }
        return $data;
    }
}
