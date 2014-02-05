<div class="news view">
<h2>News</h2>
<h3>June 2012</h3>
<p><b>Audit</b><br>
There is now log on every login, logout, addition, change and deletion.</p>

<p><b>Access Control granulation</b><br>
There is Access Control, an user must be bound to a users-role,<br>
so we are able to grant global add, modify and publish rights.</p>

<h3>April 2012</h3>
<p><b>REST API (output)</b><br>
From now on you can use the REST API that uses this XML export. For more information check out the export page.<br>
If you want to play with it manually, just add <code>.xml</code> to any url <small>(events or attributes)</small> and you should see the page rendered in XML.</p>

<h3>March 2012</h3>
<p><b>Printing</b><br>
A special CSS exists now to give a better layout when printing pages.
All the pages should now look a lot better on paper.</p>

<p><b>File upload</b><br>
Andrzej Dereszowski (NCIRC) added the file-uploading functionality. Malware samples are password protected with the password <em>infected</em>.</p>

<p><b>Backend rewrite + security</b><br>
Complete rewrite of the backend code to migrate to CakePHP 2.x (from CakePHP 1.3). <br>
During this rewrite the code was cleaned up, CSRF protection should now be present on all the important actions.<br>
Password strength validation and better security has been implemented.<br>
Signatures are now known as Attributes.<br>
Many known bugs have been fixed.</p>

<h3>March 2012</h3>
<p><b>Terms and News</b><br>
Terms and conditions have been enabled. You should only see this page once.<br>
When new software updates of MISP are installed you will see the news page.</p>

<h3>February 2012</h3>
<p><b>Automation</b><br>
It is now possible to batch import attributes. To do this simply check the
<em>batch import</em> box and insert one attribute per line in the value field.</p>

<p><b>Network IDS</b><br>
You can now customize your <em>NIDS start SID</em> in your profile.<br>
Using this feature you can choose your own range of SID and avoid any conflict with your IDS solution.</p>

<p><b>Members statistics</b><br>
On the members list page you can now see how many attributes, of what type have been uploaded by what organisation.</p>

<p><b>Text based Export</b><br>
Text based export for all the attribute types.</p>

<h3>January 2012</h3>
<p><b>Related Events</b><br>
When two Events have at least one common attribute a link is automatically made between these two events.<br>
This way you can quickly see the relations and look at the other events that might be of interest to you.</p>

<p><b>Minor UI improvements</b><br>
Fonts are smaller and the screen is better used, and the event ID is shown again.</p>

<p><b>Contact Reporter</b><br>
You can add a custom message when you want to contact the reporter of the event.<br>
This way you can already ask questions, or propose an alternative way to communicate about the event.</p>

<p><b>Privacy Improvements</b><br>
First of all, the organisation name of the reporter is not shown anymore in the events list, details of the event, and exports.<br>
Using the members list button you can see a list of the organisations and the number of members registered on the platform.</p>

<p><b>Security Improvements</b><br>
XSRF protection has been added on some (but not yet all) pages.<br>
You can now reset your authentication key (key for automatic exports) if it is compromised.<br>
The authkey generation algorithm has also been improved.</p>

<p><b>Network IDS Export</b><br>
A bug in the DNS attributes has been corrected.</p>

</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'news'));
?>

