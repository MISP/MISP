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
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<?php echo $this->Html->charset(); ?>
	<title>
		<?php echo Configure::read('CyDefSIG.name')?>:
		<?php echo $title_for_layout; ?>
	</title>
	<?php
		echo $this->Html->meta('icon');

		echo $this->Html->css('cake.generic');
        echo $this->Html->css(array('print'), 'stylesheet', array('media' => 'print'));

		echo $this->fetch('meta');
		echo $this->fetch('css');
		echo $this->fetch('script');

		echo $this->Html->script('jquery-1.7.2.min'); // Include jQuery library
	?>
</head>
<body>
	<div id="container">
		<div id="header">
			<h1><?php echo $this->Html->link(Configure::read('CyDefSIG.header'), array('controller' => 'events', 'action' => 'index')); ?>
			<?php if($logo = Configure::read('CyDefSIG.logo')) {
			echo "<img src=\"$logo\" align=\"right\" height=\"30\">";
			}?></h1>
		</div>
		<div id="content">
			<?php echo $this->Session->flash('auth'); ?>
            <?php echo $this->Session->flash('error'); ?>
		    <?php echo $this->Session->flash('gpg'); ?>
			<?php echo $this->Session->flash(); ?>
			<?php echo $this->Session->flash('email'); ?>


			<?php echo $this->fetch('content'); ?>
		</div>
		<div id="footer">
			<div class="noprint">
			    <h1 style="float:left;">Download: <?php echo $this->Html->link('PGP/GPG key', '/gpg.asc');?></h1>
			    <h1 style="float:right;"> <?php echo $this->Html->link(__('Log out', true), array('controller' => 'users', 'action' => 'logout'));?></h1>
			</div>

			<h1 style="text-align:center;"><?php echo Configure::read('CyDefSIG.footer')?></h1>
		</div>
	</div>
	<?php echo $this->element('sql_dump'); ?>
</body>
</html>
