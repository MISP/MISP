<?php

namespace App\Controller\Component;

use Cake\Controller\Component;
use Cake\Http\Exception\NotFoundException;
use Cake\Validation\Validation;

class ToolboxComponent extends Component
{
    public function findIdByUuid($model, $id, $allowEmpty = false)
    {
        if (empty($id) && $allowEmpty) {
            return $id;
        }
        if (Validation::uuid($id)) {
            $data = $model->find(
                'all',
                [
                    'conditions' => [$model->getAlias() . '.uuid' => $id],
                    'recursive' => -1,
                    'fields' => [$model->getAlias() . '.id']
                ]
            )->first();
            if (empty($data)) {
                throw new NotFoundException(__('Invalid {0}.', $model->getAlias()));
            }
            return $data['id'];
        } else {
            if (!is_numeric($id)) {
                throw new NotFoundException(__('Invalid {0}.', $model->getAlias()));
            }
            $data = $model->find(
                'all',
                [
                    'conditions' => [$model->getAlias() . '.id' => $id],
                    'recursive' => -1,
                    'fields' => [$model->getAlias() . '.id']
                ]
            )->first();
            if (empty($data)) {
                throw new NotFoundException(__('Invalid {0}.', $model->getAlias()));
            } else {
                return $id;
            }
        }
    }
}
