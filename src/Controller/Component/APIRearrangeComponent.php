<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use App\Model\Entity\User;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\ForbiddenException;
use Cake\ORM\TableRegistry;
use Cake\Core\Configure;
use Cake\Core\Configure\Engine\PhpConfig;
use Cake\Utility\Inflector;
use Cake\Routing\Router;
use Cake\Collection\Collection;

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
            $data->each(function ($value, $key) use (&$newData) {
                $value->rearrangeForAPI();
                $newData[] = $value;
            });
            return new Collection($newData);
        } else {
            $data->rearrangeForAPI();
        }
        return $data;
    }
}