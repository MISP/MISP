<?php
App::uses('AppModel', 'Model');

class AdminSetting extends AppModel
{
    public $useTable = 'admin_settings';

    public $actsAs = array(
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ),
        'Containable'
    );

    public $validate = array('setting' => 'isUnique');

    public function changeSetting($setting, $value = false)
    {
        $existing = $this->find('first', array(
            'conditions' => array('setting' => $setting),
            'fields' => ['id'],
        ));
        if ($existing) {
            if ($this->save([
                'id' => $existing['AdminSetting']['id'],
                'value' => $value,
            ])) {
                return true;
            } else {
                return $this->validationErrors;
            }
        } else {
            $this->create();
            $existing['AdminSetting'] = array('setting' => $setting, 'value' => $value);
            if ($this->save($existing)) {
                return true;
            } else {
                return $this->validationErrors;
            }
        }
    }

    public function getSetting($setting)
    {
        $setting_object = $this->find('first', array(
            'conditions' => array('setting' => $setting),
            'fields' => ['value'],
        ));
        if (!empty($setting_object)) {
            return $setting_object['AdminSetting']['value'];
        } else {
            return false;
        }
    }

    public function updatesDone($blocking = false)
    {
        if ($blocking) {
            $continue = false;
            while ($continue == false) {
                $db_version = $this->find('first', array('conditions' => array('setting' => 'db_version')));
                $continue = empty($this->findUpgrades($db_version['AdminSetting']['value']));
            }
            return true;
        } else {
            $db_version = $this->find('first', array('conditions' => array('setting' => 'db_version')));
            return empty($this->findUpgrades($db_version['AdminSetting']['value']));
        }
    }

    public function garbageCollect()
    {
        $last_collection = $this->find('first', [
            'conditions' => ['setting' => 'last_gc_timestamp'],
            'recursive' => -1
        ]);
        if (empty($last_collection)) {
            $last_collection = 0;
        } else {
            $last_collection = $last_collection['AdminSetting']['value'];
        }
        if ((time()) > ($last_collection + 3600)) {
            $this->__cleanTmpFiles();
        }
    }

    private function __cleanTmpFiles() {
        $time = time();
        $this->__deleteScriptTmpFiles($time);
        $this->__deleteTaxiiTmpFiles($time);
        $this->__deleteCachedExportFiles($time);
    }

    private function __deleteScriptTmpFiles($time) {
        $scripts_tmp_path = APP . 'files/scripts/tmp';
        $dir = new Folder($scripts_tmp_path);
        $contents = $dir->read(false, false);
        foreach ($contents[1] as $file) {
            if (preg_match('/^[a-zA-Z0-9]{12}$/', $file)) {
                $tmp_file = new File($scripts_tmp_path . '/' . $file);
                if ($time > $tmp_file->lastChange() + 3600) {
                    $tmp_file->delete();
                }
                unlink($scripts_tmp_path . '/' . $file);
            }
        }
    }

    private function __deleteCachedExportFiles($time) {
        $cache_path = APP . 'tmp/cached_exports';
        $cache_dir = new Folder($cache_path);
        $cache_data = $cache_dir->read(false, false);
        if (!empty($cache_data[0])) {
            foreach ($cache_data[0] as $cache_export_dir) {
                $tmp_dir = new Folder($cache_path . '/' . $cache_export_dir);
                $cache_export_dir_contents = $tmp_dir->read(false, false);
                if (!empty(count($cache_export_dir_contents[1]))) {
                    $files_count = count($cache_export_dir_contents[1]);
                    $files_removed = 0;
                    foreach ($cache_export_dir_contents[1] as $tmp_file) {
                        $tmp_file = new File($cache_path . '/' . $cache_export_dir . '/' . $tmp_file);
                        if ($time > $tmp_file->lastChange() + 3600) {
                            $tmp_file->delete();
                            $files_removed += 1;
                        }
                    }
                }
            }
        }
    }

    private function __deleteTaxiiTmpFiles($time) {
        $taxii_path = APP . 'files/scripts/tmp/Taxii';
        $taxii_dir = new Folder($taxii_path);
        $taxii_contents = $taxii_dir->read(false, false);
        if (!empty($taxii_contents[0])) {
            foreach ($taxii_contents[0] as $taxii_temp_dir) {
                if (preg_match('/^[a-zA-Z0-9]{12}$/', $taxii_temp_dir)) {
                    $tmp_dir = new Folder($taxii_path . '/' .$taxii_temp_dir);
                    $taxii_temp_dir_contents = $tmp_dir->read(false, false);
                    if (!empty(count($taxii_temp_dir_contents[1]))) {
                        $files_count = count($taxii_temp_dir_contents[1]);
                        $files_removed = 0;
                        foreach ($taxii_temp_dir_contents[1] as $tmp_file) {
                            $tmp_file = new File($taxii_path . '/' . $taxii_temp_dir . '/' . $tmp_file);
                            if ($time > $tmp_file->lastChange() + 3600) {
                                $tmp_file->delete();
                                $files_removed += 1;
                            }
                        }
                        if ($files_count === $files_removed) {
                            $tmp_dir->delete();
                        }
                    }
                }
            }
        }
    }
}
