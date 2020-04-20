<?php

class ToolboxComponent extends Component
{
    public function findIdByUuid($model, $id, $allowEmpty = false) {
        if (empty($id) && $allowEmpty) {
            return $id;
        }
        if (Validation::uuid($id)) {
            $data = $model->find('first', array(
                'conditions' => array($model->alias . '.uuid' => $id),
                'recursive' => -1,
                'fields' => array($model->alias . '.id')
            ));
            if (empty($data)) {
                throw new NotFoundException(__('Invalid %s.', $model->alias));
            }
            return $data[$model->alias]['id'];
        } else {
            if (!is_numeric($id)) {
                throw new NotFoundException(__('Invalid %s.', $model->alias));
            }
            $data = $model->find('first', array(
                'conditions' => array($model->alias . '.id' => $id),
                'recursive' => -1,
                'fields' => array($model->alias . '.id')
            ));
            if (empty($data)) {
                throw new NotFoundException(__('Invalid %s.', $model->alias));
            } else {
                return $id;
            }
        }
    }
}
