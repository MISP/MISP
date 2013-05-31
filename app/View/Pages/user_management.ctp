<div class="actions" style="width:15%">
	<ol class="nav nav-list">
		<li><?php echo $this->Html->link('General Layout', array('controller' => 'pages', 'action' => 'display', 'documentation')); ?></li>
		<li class="active"><?php echo $this->Html->link('User Management and Global actions', array('controller' => 'pages', 'action' => 'display', 'user_management')); ?>
			<ul class="nav nav-list">
				<li><a href="#first_run">First run of the system</a></li>
				<li><a href="#manage">Managing your account</a></li>
				<li><a href="#uptodate">Staying up to date</a></li>
			</ul>
		</li>
		<li><?php echo $this->Html->link('Using the system', array('controller' => 'pages', 'action' => 'display', 'using_the_system')); ?></li>
		<li><?php echo $this->Html->link('Administration', array('controller' => 'pages', 'action' => 'display', 'administration')); ?></li>
		<li><?php echo $this->Html->link('Categories and Types', array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?></li>
	</ol>
</div>
<div class="index" style="width:80%">
	<h2>User Management and Global Actions</h2>
	<a name="first_run"></a>
	<h3>First run of the system:</h3>
	When first logging into MISP with the username and password provided by your administrator, there are a number of things that need to be done, before you can start using the system.<br><br>
	<ul>
		<li><em>Acceping the Terms of use:</em> The terms of use are shown immediately after logging in for the first time, make sure to read through this page before clicking "Accept Terms" at the bottom of the page.<br /><br /></li>
		<li><em>Changing the password:</em> After accepting the ToU, you'll be prompted to change your password, but keep in mind that it has to be at least 6 characters long, it has to include at least one upper-case and one lower-case character in addition to a digit or a special character. Enter the same password into the confirm password field, before clicking submit to finalise the change.<br /><br />
		<p><img src="/img/doc/password.png" alt = "" title="Changing the password"></p><br /></li>
		<li><em>Setting up the GPG Key:</em> In order for the system to be able to encrypt the messages that you send through it, it needs to know your GPG key. Navigate to the Edit profile view (My Profile on the left -&gt; Edit profile in the top right corner). Paste the key into the Gpgkey field and click submit.<br /><br />
		<p><img src="/img/doc/alerts.png" alt = "" title="Use these checkboxes to subscribe to auto-alerts and contact reporter e-mails."></p><br /></li>
		<li><em>Subscribing to Auto-alerts:</em> Turning auto-alerts on will allow the system to send you e-mail notifications about any new public events entered into the system by other users and private events added by members of your organisation. To turn this on, navigate to the Edit profile view (My profile on the left navigation menu -&gt; Edit profile in the top right corner). Tick the auto-alert checkbox and click submit to enable this feature.<br /><br />
		<li><em>Subscribing to e-mails sent via the "Contact Reporter" functionality:</em> This feature is turned on right below the autoalerts and will allow you to receive e-mails addressed to your organisation whenever a user tries to ask about an event that was posted by a user of your organisation. Keep in mind that you can still be addressed by such a request even when this setting is turned off, if someone tries to contact you as the event creator directly or your organisation for an event that you personally have created then you will be notified.<br /><br />
		<li><em>Reviewing the Terms &amp; Conditions:</em> To review the Terms &amp; Conditions or to read the User Guide, use the appropriate button on the left navigation menu.<br /><br /></li>
		<li><em>Making sure that compatibility mode is turned off (IE9&amp;IE10):</em>Compatibility mode can cause some elements to appear differently than intended or not appear at all. Make sure you have this option turned off.</li></ul>
<hr />
<a name="manage"></a><h3>Managing your account:</h3>
To alter any details regarding your profile, use the "My Profile" menu button to bring up the profile overview and then click on "Edit Profile" in the right upper corner.<br>
<ul>
	<li style="list-style: none">
		<p><img src="/img/doc/edit_user.png" alt = "" style="float:right;" title="Change any of your profile settings here."></p><br>
	</li>
	<li><em>Changing your e-mail address:</em> Your e-mail address serves as both a login name and as a means of communication with other users of the MISP system via the contact reporter feature. To change your e-mail address, just enter the edit profile menu (My profile on the left navigation menu -&gt; Edit profile in the top right corner) and change the field titled Email.<br /><br /></li>
	<li><em>Changing the password:</em> As a next step, change the password provided by your administrator to something of your own choosing. Click on My profile on the left navigation menu, under Global Actions, which will bring up the User view. Click on Edit User on the left navigation menu or Edit Profile in the top right corner. This next screen, allows you to edit your details, including your password, by filling out the password field. Keep in mind that the password has to be at least 6 characters long, has to include at least one upper-case and one lower-case character in addition to a digit or a special character. Enter the same password into the confirm password field, before clicking submit to finalise the change.<br /><br /></li>
	<li><em>Subscribing to Auto-alerts:</em> Turning auto-alerts on will allow the system to send you e-mail notifications about any new public events entered into the system by other users and private events added by members of your organisation. To turn this on, navigate to the Edit profile view (My profile on the left navigation menu -&gt; Edit profile in the top right corner). Tick the auto-alert checkbox and click submit to enable this feature.<br /><br /></li>
	<li><em>Subscribing to e-mails sent via the "Contact Reporter" functionality:</em> Turning this feature on will allow you to receive e-mails addressed to your organisation whenever a user tries to ask about an event that was posted by a user of your organisation. Keep in mind that you can still be addressed by such a request even when this setting is turned off, if someone tries to contact the person that reported an event that you yourself have created.<br /><br /></li>
	<li><em>Setting up the GPG Key:</em> In order for the system to be able to encrypt the messages that you send through it, it needs to know your GPG key. You can acquire this by clicking on the PGP/GPG key link at the bottom left of the screen. Copy the entirety of the key and navigate to the Edit profile view (My Profile on the left -&gt; Edit profile in the top right corner). Paste the key into the Gpgkey field and click submit.<br /><br /></li>
	<li><em>Requesting a new authentication key:</em> It is possible to make the system generate a new authentication key for you (for example if your previous one gets compromised. This can be accessed by clicking on the My Profile button and then clicking the reset key next to the currently active authentication code. The old key will become invalid when the new one is generated.<br /><br />
	<p><img src="/img/doc/reset.png" alt = "" title="Clicking on reset will generate a new key for you and invalidate the old one, blocking it from being used."></p></li></ul>
<hr />
 <a name="uptodate"></a><h3>Staying up to date:</h3>
MISP also provides its users with some information about itself and its users through the links provided in the Global Actions menu.<br><br>
<ul>
	<li><em>News:</em> To read about the news regarding the system itself, click on News on the left menu. This will bring up a list of news items concerning updates and changes to MISP itself.<br /><br /></li>
	<li><em>Member statistics:</em> By using the Members List menu button on the left, you can get a quick overview over how many users each organisation has registered on your server, and a histogram, depicting the distribution of attribute types created by each organisation.<br /><br /></li>
	<li><em>User Guide:</em> The user guide is also accessible via the Global Actions menu. You can find out more about how to use the system by reading this.<br /><br /></li>
	<li><em>Terms &amp; Conditions:</em> It is possible to review the terms &amp; conditions that were shown during the first run of the system by clicking on the terms &amp; conditions link in the Global Actions menu.<br /><br /></li>
</ul>
 <a name="filters"></a><h3>Inspecting the input filters:</h3>
All the events and attributes that get entered into MISP will be run through a series of input filters. These are defined by the site administrators, but every user can take a look at the currently active lists.<br><br>
<ul>
	<li><em>Import Blacklist:</em> Events with the info field containing or Attributes with a value containing any of the items listed in the Import Blacklist will be blocked from being entered.<br /><br /></li>
	<li><em>Import Regexp:</em> All Attribute value and Event info fields will be parsed for a set of regular expressions and replaced based on the replacement values contained in this section. This has many uses, such as unifying similar data for better correlation, removing personal data from file-paths or simply for clarity.<br /><br /></li>
	<li><em>Signature Whitelist:</em> This list (can) contain a set of addresses that are allowed to be entered as attribute values but will be blocked from being exported to NIDS-es.<br /><br /> </li>
</ul>
</div>

