<?php
App::uses('AppModel', 'Model');
class Dashboard extends AppModel
{
    public $useTable = false;

    public function loadWidget($user, $name)
    {
        if (file_exists(APP . 'Lib/Dashboard/' . $name . '.php')) {
            App::uses($name, 'Dashboard');
        } else if (file_exists(APP . 'Lib/Dashboard/Custom/' . $name . '.php')) {
            App::uses($name, 'Dashboard/Custom');
        } else {
            throw new NotFoundException(__('Invalid widget or widget not found.'));
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
        $dir = new Folder(APP . 'Lib/Dashboard');
        $customdir = new Folder(APP . 'Lib/Dashboard/Custom');
        $widgetFiles = $dir->find('.*Widget\.php');
        $customWidgetFiles = $customdir->find('.*Widget\.php');
        $widgets = array();
        foreach ($widgetFiles as $widgetFile) {
            $className = substr($widgetFile, 0, strlen($widgetFile) -4);
            $temp = $this->__extractMeta($user, $className, false);
            if ($temp !== false) {
                $widgets[$className] = $temp;
            }
        }
        foreach ($customWidgetFiles as $widgetFile) {
            $className = substr($widgetFile, 0, strlen($widgetFile) -4);
            $temp = $this->__extractMeta($user, $className, true);
            if ($temp !== false) {
                $widgets[$className] = $temp;
            }
        }
        return $widgets;
    }

    private function __extractMeta($user, $className, $custom)
    {
        App::uses($className, 'Dashboard' . ($custom ? '/Custom' : ''));
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
            'placeholder' => empty($widgetClass->placeholder) ? '' : $widgetClass->placeholder
        );
        return $widget;
    }
}
