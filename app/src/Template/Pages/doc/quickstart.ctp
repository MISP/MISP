<div class="actions <?php echo $debugMode;?>">
	<ol class="nav nav-list">
		<li class="active"><?php echo $this->Html->link('Quick Start', array('controller' => 'pages', 'action' => 'display', 'doc', 'quickstart')); ?></li>
		<li><?php echo $this->Html->link('General Layout', array('controller' => 'pages', 'action' => 'display', 'doc', 'general')); ?></li>
		<li><?php echo $this->Html->link('General Concepts', array('controller' => 'pages', 'action' => 'display', 'doc', 'concepts')); ?></li>
		<li><?php echo $this->Html->link('User Management and Global actions', array('controller' => 'pages', 'action' => 'display', 'doc', 'user_management')); ?></li>
		<li><?php echo $this->Html->link('Using the system', array('controller' => 'pages', 'action' => 'display', 'doc', 'using_the_system')); ?></li>
		<li><?php echo $this->Html->link('Administration', array('controller' => 'pages', 'action' => 'display', 'doc', 'administration')); ?></li>
		<li><?php echo $this->Html->link('Categories and Types', array('controller' => 'pages', 'action' => 'display', 'doc', 'categories_and_types')); ?></li>
	</ol>
</div>

<div class="index">
<h2>Quick Start</h2>
<p>The Malware Information Sharing Platform (MISP) is the tool which will be used to facilitate the exchange of Indicator of Compromise (IOC) about
targeted malware and attacks within your community of trusted members. It is a central Indicator of Compromise (IOC) database with technical and
non-technical information. Exchanging this information should result in faster detection of targeted attacks and improve the detection ratio,
while also reducing the number of false positives.</p>
<h3>Create an Event</h3>
	<p><img src="<?php echo $baseurl;?>/img/doc/quick_create.jpg" alt = "" title = ""/></p>
<h3>Browsing past Events</h3>
	<p><img src="<?php echo $baseurl;?>/img/doc/quick_browse.jpg" alt = "" title = ""/></p>
<h3>Export Events for logsearches</h3>
	<p><img src="<?php echo $baseurl;?>/img/doc/quick_export.jpg" alt = "" title = ""/></p>

</div>
