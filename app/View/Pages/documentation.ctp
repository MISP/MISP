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
	The top bar's only interactive part is a link to the MISP system itself - this will redirect the user to the default view of the site, which is the List Events view.<br />
	<h3>The left menu</h3>
	This menu contains all of the main functions of the site as a series of buttons.<br />
	<p><img src="/img/doc/menu_image.png" alt = "" style="float:right;" title = "This is the main menu that will be accessible from all of the views. In some instances, some additional buttons that will appear on top of these when a view provides it."/></p>
	<ul>
		<li><em>New Event:</em> Allows you to create a new event.</li>
		<li><em>List Events:</em> You can browse all the currently stored events here.</li>
		<li><em>List Attributes:</em> You can browse all the currently stored attributes of events here.</li>
		<li><em>Search Attributes:</em> Search for and filter a list of attributes.</li>
		<li><em>Export:</em> Export various types of data from the system for NIDSs or other uses.<br /></li></ul>
	<i><u>Global Actions</u></i><br />
	<ul>
		<li><em>News:</em> Read about the latest news regarding the MISP system</li>
		<li><em>My Profile:</em> Manage your user account.</li>
		<li><em>Members List:</em> View the number of users per organisation and get some statistics about the currently stored attributes.</li>
		<li><em>User Guide:</em> A link to this user guide.</li>
		<li><em>Terms &amp; Conditions:</em> View the terms &amp; conditions again.</li>
		<li><em>Log out:</em> Logs the current user out.<br /></li></ul>
	<i><u>Sync Actions</u></i><br />
	<ul>
		<li><em>List Servers:</em> Connect your MISP instance to other instances, or view and modify the currently established connections.<br /></li></ul>
	<i><u>Input Filters</u></i><br />
	<ul>
		<li><em>Import Blacklist:</em> Create, modify or delete blacklisted strings. These will stop any matching events/attributes from being entered into the system.</li>
		<li><em>Import Regexp:</em> Create, modify or delete regular expressions and their replacements. Each time an event / attribute is created or modified, they will be parsed and found expressions will be replaced.</li>
		<li><em>Signature Whitelist:</em> View and manage the list of whitelisted addresses. These, if contained in attributes, will be blocked from the NIDS signature exports.<br /></li></ul>
	<i><u>Administration</u></i><br />
	<ul>
		<li><em>New User:</em> Create an account for a new user.</li>
		<li><em>List Users:</em> View, modify or delete the currently registered users.</li>
		<li><em>New Role:</em> Create a new role group for the users of this instance, controlling their privileges to create, modify, delete and to publish events.</li>
		<li><em>List Roles:</em> List, modify or delete currently existing roles.<br /></li></ul>
	<i><u>Audit</u></i><br />
	<ul>
		<li><em>List Logs:</em> View the logs of the instance.</li>
		<li><em>Search Logs:</em> Search the logs by various attributes.<br /></li></ul>

<h3>The main area</h3>
	This is where all the views (navigated to via the menu buttons) will be displayed. In general, there are two main view types, information views (which list the currently stored data and allow you to modify it) and form views (allowing you to enter or alter data). All lists are organised in such a way that all the information columns are on the left and every line of data can be modified or viewed in more detail on the right-most column, titled "Actions". All lists display a certain set number of the most recent items, but page control buttons at the bottom allow you to browse older entries.<br />
<h3>The bottom bar</h3>
	Contains a link to download the gpg key used for encrypting the e-mails sent through the system and the current version number - if you are logged in.<br />
	<p><img src="/img/doc/bottom_bar.png" alt = "" style="float:left;" title = "Download your PGP/GPG key using the link on the bottom bar or log out."/></p><br />

</div>
