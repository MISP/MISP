<div class="actions" style="width:15%">
	<ol class="nav nav-list">
		<li class="active"><?php echo $this->Html->link('General Layout', array('controller' => 'pages', 'action' => 'display', 'documentation')); ?></li>
		<li><?php echo $this->Html->link('User Management and Global actions', array('controller' => 'pages', 'action' => 'display', 'user_management')); ?></li>
		<li><?php echo $this->Html->link('Using the system', array('controller' => 'pages', 'action' => 'display', 'using_the_system')); ?></li>
		<li><?php echo $this->Html->link('Administration', array('controller' => 'pages', 'action' => 'display', 'administration')); ?></li>
		<li><?php echo $this->Html->link('Categories and Types', array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?></li>
	</ol>
</div>

<div class="index" style="width:80%">
<h2>General Layout</h2>
<h3>The top bar</h3>
	<p>This menu contains all of the main functions of the site as a series of buttons.</p>
	<p><img src="/img/doc/menu_image.png" alt = "" style="float:right;" title = "This is the main menu that will be accessible from all of the views. In some instances, some additional buttons that will appear on top of these when a view provides it."/></p>
	<ul>
		<li><em>List Events:</em> You can browse all the currently stored events here.</li>
		<li><em>Add Event:</em> Allows you to create a new event.</li>
		<li><em>List Attributes:</em> You can browse all the currently stored attributes of events here.</li>
		<li><em>Search Attributes:</em> Search for and filter a list of attributes.</li>
		<li><em>Export:</em> Export various types of data from the system for NIDSs or other uses.</li>
		<li><em>Automation:</em> Automation functionality is designed to let tools access the data. </li>
	</ul>

	<h5>Input Filters</h5>
	<ul>
		<li><em>Import Blacklist:</em> Create, modify or delete blacklisted strings. These will stop any matching events/attributes from being entered into the system.</li>
		<li><em>Import Regexp:</em> Create, modify or delete regular expressions and their replacements. Each time an event / attribute is created or modified, they will be parsed and found expressions will be replaced.</li>
		<li><em>Signature Whitelist:</em> View and manage the list of whitelisted addresses. These, if contained in attributes, will be blocked from the NIDS signature exports.</li>
	</ul>

	<h5>Global Actions</h5>
	<ul>
		<li><em>News:</em> Read about the latest news regarding the MISP system</li>
		<li><em>My Profile:</em> Manage your user account.</li>
		<li><em>Members List:</em> View the number of users per organisation and get some statistics about the currently stored attributes.</li>
		<li><em>User Guide:</em> A link to this user guide.</li>
		<li><em>Terms &amp; Conditions:</em> View the terms &amp; conditions again.</li>
		<li><em>Log out:</em> Logs the current user out.</li>
	</ul>

	<h5>Sync Actions</h5>
	<ul>
		<li><em>List Servers:</em> Connect your MISP instance to other instances, or view and modify the currently established connections.</li></ul>


	<h5>Administration</h5>
	<ul>
		<li><em>New User:</em> Create an account for a new user.</li>
		<li><em>List Users:</em> View, modify or delete the currently registered users.</li>
		<li><em>New Role:</em> Create a new role group for the users of this instance, controlling their privileges to create, modify, delete and to publish events.</li>
		<li><em>List Roles:</em> List, modify or delete currently existing roles.</li>
		<li><em>Contact Users:</em> You can use this view to send messages to your current or future users or send them a temporary password.</li>
	</ul>

	<h5>Audit</h5>
	<ul>
		<li><em>List Logs:</em> View the logs of the instance.</li>
		<li><em>Search Logs:</em> Search the logs by various attributes.</li>
	</ul>
<h3>The left bar</h3>
	<p>This bar changes based on each page-group. The blue selection shows you what page you are on.</p>

<h3>The main area</h3>
	<p>This is where all the views (navigated to via the menu buttons) will be displayed.
	In general, there are two main view types, information views (which list the currently
	stored data and allow you to modify it) and form views (allowing you to enter or alter data).
	All lists are organised in such a way that all the information columns are on the left and every
	line of data can be modified or viewed in more detail on the right-most column, titled "Actions".
	All lists display a certain set number of the most recent items, but page control buttons at the
	bottom allow you to browse older entries.</p>
<h3>The bottom bar</h3>
	<p>Contains a link to download the gpg key used for encrypting the e-mails sent through the system and the current version number - if you are logged in.</p>
	<p><img src="/img/doc/bottom_bar.png" alt = "" style="float:left;" title = "Download your PGP/GPG key using the link on the bottom bar or log out."/></p>

</div>
