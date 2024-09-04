<?php
/**
 * Static content controller.
 *
 * This file will render views from views/pages/
 *
 * PHP 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       app.Controller
 * @since         CakePHP(tm) v 0.2.9
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

App::uses('AppController', 'Controller');

class PagesController extends AppController
{
    public $name = 'Pages';
    public $uses = array();

    // displays a view based on the page to display passed as parameters
    public function display()
    {
        $path = func_get_args();
        foreach ($path as $k => $part) {
            if (strpos($part, '..') !== false || strpos($part, '/') !== false) {
                unset($path[$k]);
            }
        }
        $path = array_values($path);
        $count = count($path);
        if (!$count) {
            $this->redirect('/');
        }
        $page = $subpage = $title_for_layout = null;

        if (!empty($path[0])) {
            $page = $path[0];
        }
        if (!empty($path[1])) {
            $subpage = $path[1];
            if ($path[1] === 'md') {
                $this->layout = false;
            }
        }
        if (!empty($path[$count - 1])) {
            $title_for_layout = Inflector::humanize($path[$count - 1]);
        }
        $this->loadModel('MispAttribute');
        $this->set('categoryDefinitions', $this->MispAttribute->categoryDefinitions);
        $this->set('typeDefinitions', $this->MispAttribute->typeDefinitions);
        $this->set('user', $this->Auth->User());
        $this->set(compact('page', 'subpage', 'title_for_layout'));
        $this->render(implode('/', $path));
    }
}
