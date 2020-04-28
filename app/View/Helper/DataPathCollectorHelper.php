<?php
    /*
     * Helper used to extract variables from an array based on path
     * Used by the index factories
     *
     */
    App::uses('AppHelper', 'View/Helper');
        class DataPathCollectorHelper extends AppHelper {
            public function extract($data, $data_path, $options = array())
            {
                $result = array();
                if (!is_array($data_path)) {
                    $data_path = array($data_path);
                }
                foreach ($data_path as $path) {
                    $temp = Hash::extract($data, $path);
                    if (is_array($temp)) {
                        if (count($temp) > 1) {
                            $temp = implode(', ', $temp);
                        } else {
                            if (count($temp) > 0) {
                                $temp = $temp[0];
                            } else {
                                $temp = '';
                            }
                        }
                    }
                    $result[$path] = $temp;
                }
                return $result;
            }
        }
