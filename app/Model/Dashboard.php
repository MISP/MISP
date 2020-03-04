<?php
App::uses('AppModel', 'Model');
class Dashboard extends AppModel
{
    public $useTable = false;

    public function loadWidget($user, $name)
    {
        $name = str_replace('/', '', $name);
        if (file_exists(APP . 'Lib/Dashboard/' . $name . '.php')) {
            App::uses($name, 'Dashboard');
        } else if (file_exists(APP . 'Lib/Dashboard/Custom/' . $name . '.php')) {
            App::uses($name, 'Dashboard/Custom');
        } else {
            $customdir = new Folder(APP . 'Lib/Dashboard/Custom');
            $subDirectories = $customdir->read();
            $found = false;
            foreach ($subDirectories[0] as $subDir) {
                $currentDir = new Folder(APP . 'Lib/Dashboard/' . $subDir);
                if (file_exists(APP . 'Lib/Dashboard/Custom/' . $subDir . '/' . $name . '.php')) {
                    App::uses($name, 'Dashboard/Custom/' . $subDir);
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                throw new NotFoundException(__('Invalid widget or widget not found.'));
            }
        }
        $widget = new $name();
        if (method_exists($widget, 'checkPermissions')) {
            if (!$widget->checkPermissions($user)) {
                throw new NotFoundException(__('Invalid widget or widget not found.'));
            }
        }
        return $widget;
    }

    public function loadAllWidgets($user)
    {
        $paths = array(
            '/',
            '/Custom'
        );
        $customdir = new Folder(APP . 'Lib/Dashboard/Custom');
        $subDirectories = $customdir->read();
        foreach ($subDirectories[0] as $subDir) {
            $paths[] = '/Custom/' . $subDir;
        }
        $widgetMeta = array();
        $widgets = array();
        foreach ($paths as $path) {
            $currentDir = new Folder(APP . 'Lib/Dashboard' . $path);
            $widgetFiles = $currentDir->find('.*Widget\.php');
            foreach ($widgetFiles as $widgetFile) {
                $className = substr($widgetFile, 0, strlen($widgetFile) -4);
                $temp = $this->__extractMeta($user, $className, $path);
                if ($temp !== false) {
                    $widgets[$className] = $temp;
                }
            }
        }
        return $widgets;
    }

    private function __extractMeta($user, $className, $path)
    {
        App::uses($className, 'Dashboard' . ($path === '/' ? '' : $path));
        $widgetClass = new $className();
        if (method_exists($widgetClass, 'checkPermissions')) {
            if (!$widgetClass->checkPermissions($user)) {
                return false;
            }
        }
        $widget = array(
            'widget' => $className,
            'title' => $widgetClass->title,
            'render' => $widgetClass->render,
            'params' => empty($widgetClass->params) ? array() : $widgetClass->params,
            'description' => empty($widgetClass->description) ?  $widgetClass->title : $widgetClass->description,
            'height' => empty($widgetClass->height) ? 1 : $widgetClass->height,
            'width' => empty($widgetClass->width) ? 1 : $widgetClass->width,
            'placeholder' => empty($widgetClass->placeholder) ? '' : $widgetClass->placeholder,
            'autoRefreshDelay' => empty($widgetClass->autoRefreshDelay) ? false : $widgetClass->autoRefreshDelay,
        );
        return $widget;
    }
}
