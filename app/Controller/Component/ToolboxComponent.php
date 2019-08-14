<?php

class ToolboxComponent extends Component
{
    public function findIdByUuid($model, $id, $allowEmpty = false) {
        if (empty($id) && $allowEmpty) {
            return $id;
        }
        if (Validation::uuid($id)) {
            $data = $model->find('first', array(
                'conditions' => array($model->name . '.uuid' => $id),
                'recursive' => -1,
                'fields' => array($model->name . '.id')
            ));
            return $data[$model->name]['id'];
        } else {
            if (!is_numeric($id)) {
                throw new NotFoundException(__('Invalid %s.', $model->name));
            }
            $data = $model->find('first', array(
                'conditions' => array($model->name . '.id' => $id),
                'recursive' => -1,
                'fields' => array($model->name . '.id')
            ));
            if (empty($data)) {
                throw new NotFoundException(__('Invalid %s.', $model->name));
            } else {
                return $id;
            }
        }
    }
}
