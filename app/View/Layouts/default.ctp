<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<?php echo $this->Html->charset(); ?>
	<title>
		<?php echo $title_for_layout, ' - ', Configure::read('CyDefSIG.name')?>:
	</title>
	<?php
		echo $this->Html->meta('icon');

// 		echo $this->Html->css('cake.generic');
		echo $this->Html->css('roboto');
		echo $this->Html->css('bootstrap'); // see http://twitter.github.io/bootstrap/base-css.html
		echo $this->Html->css('datepicker');
		echo $this->Html->css('main');

		// FIXME chri: re-add print stylesheet
		//echo $this->Html->css(array('print'), 'stylesheet', array('media' => 'print'));

		echo $this->fetch('meta');
		echo $this->fetch('css');
		echo $this->fetch('script');

		echo $this->Html->script('jquery-1.9.1.min'); // Include jQuery library
	?>

<!--?php echo $scripts_for_layout; ?-->
</head>
<body>
	<div id="container">
		<!--div id="header">
			<h1><?php echo $this->Html->link(Configure::read('CyDefSIG.header'), array('controller' => 'events', 'action' => 'index')); ?>
			<?php if ($logo = Configure::read('CyDefSIG.logo')) {
				echo $this->Html->image($logo, array('alt' => h(Configure::read('CyDefSIG.header')), 'align' => 'right', 'height' => '30'));
			}?></h1>
		</div-->
		<?php echo $this->element('global_menu');?>
		<div class="container-fluid" style="padding-top:50px;position:fixed;width:98%;">
			<?php echo $this->Session->flash('auth'); ?>
			<?php echo $this->Session->flash('error'); ?>
    		<?php echo $this->Session->flash('gpg'); ?>
			<?php echo $this->Session->flash(); ?>
			<?php echo $this->Session->flash('email'); ?>
		</div>
		<br/><br />
		<div style="margin-top:50px;">
			<?php echo $this->fetch('content'); ?>
		</div>
		<!--div id="footer">
			<div class="noprint">
			    <h1 style="float:left;">Download: <?php echo $this->Html->link('PGP/GPG key', '/gpg.asc');?></h1>
			    <h1 style="float:right;"> <?php echo $this->Html->link(__('Log out', true), array('controller' => 'users', 'action' => 'logout'));?></h1>
			</div>

			<h1 style="text-align:center;"> <?php if (isset($me)) echo Configure::read('CyDefSIG.footerversion'); else echo Configure::read('CyDefSIG.footer')?></h1>
		</div-->
	<?php
	echo $this->element('footer');
	echo $this->element('sql_dump');
	echo $this->Html->script('bootstrap');
	// echo $this->Html->script('bootstrap.min');
	echo $this->Html->script('bootstrap-datepicker');
	echo $this->Html->script('main');
	?>
	</div>
</body>
</html>
