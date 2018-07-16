<?php
/**
 *
* PHP 5
*
* CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
* Copyright 2005-2011, Cake Software Foundation, Inc. (http://cakefoundation.org)
*
* Licensed under The MIT License
* Redistributions of files must retain the above copyright notice.
*
* @copyright     Copyright 2005-2011, Cake Software Foundation, Inc. (http://cakefoundation.org)
* @link          http://cakephp.org CakePHP(tm) Project
* @package       Cake.View.Layouts
* @since         CakePHP(tm) v 0.10.0.1076
* @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
*/
?>
<?php
//echo $this->Html->css('roboto');
echo $this->Html->css('bootstrap');
echo $this->Html->css('bootstrap-datepicker');
echo $this->Html->css('bootstrap-timepicker');
echo $this->Html->css('bootstrap-colorpicker');
echo $this->Html->css('famfamfam-flags');
echo $this->Html->css('font-awesome');
echo $this->Html->script('jquery');
echo $this->Html->script('bootstrap');
echo $this->Html->script('bootstrap-timepicker');
echo $this->Html->script('bootstrap-datepicker');
echo $this->Html->script('bootstrap-colorpicker');
echo $this->Html->script('misp.js?' . $queryVersion);
echo $this->Html->script('keyboard-shortcuts.js?' . $queryVersion);
echo $content_for_layout; ?>
