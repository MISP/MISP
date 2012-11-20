<div class="index">
<b>Table of contents</b><br>
1. <?php echo $this->Html->link(__('General Layout', true), array('controller' => 'pages', 'action' => 'display', 'documentation')); ?><br>
2. <?php echo $this->Html->link(__('User Management and Global Actions', true), array('controller' => 'pages', 'action' => 'display', 'user_management')); ?><br>
<ul>
	<li>a. <a href="#first_run">First run of the system</a></li>
	<li>b. <a href="#manage">Managing your account</a></li>
	<li>c. <a href="#uptodate">Staying up to date</a></li>
</ul>
3. <?php echo $this->Html->link(__('Using the system', true), array('controller' => 'pages', 'action' => 'display', 'using_the_system')); ?><br>
4. <?php echo $this->Html->link(__('Administration', true), array('controller' => 'pages', 'action' => 'display', 'administration')); ?><br>
5. <?php echo $this->Html->link(__('Categories and Types', true), array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?>
<p></p>
<hr/><br>
<h2>User Management and Global Actions</h2>
	<a name ="first_run"></a><h3>First run of the system:</h3>
		When first logging into MISP with the username and password provided by your administrator, there are a number of things that need to be done, before you can start using the system.<br><br>
		<ul>
			<li><em>Acceping the Terms of use:</em> The terms of use are shown immediately after logging in for the first time, make sure to read through this page before clicking "Accept Terms" at the bottom of the page.</li><br>
			<li><em>Changing the password:</em> As a next step, change the password provided by your administrator to something of your own choosing. Click on My profile on the left navigation menu, under Global Actions, which will bring up the User view. Click on Edit User on the left navigation menu or Edit Profile in the top right corner. This next screen, allows you to edit your details, including your password, by filling out the password field, but keep in mind that the password has to be at least 6 characters long, has to include at least one upper-case and one lower-case character in addition to a digit or a special character. Enter the same password into the confirm password field, before clicking submit to finalise the change.<br><br>
			<p><img src="/img/doc/add_server.png" title = "Changing the password"/></p><br></li>
			<li><em>Setting up the GPG Key:</em> In order for the system to be able to encrypt the messages that you send through it, it needs to know your GPG key. You can acquire this by clicking on the PGP/GPG key link at the bottom left of the screen, then copy the entirety of the key and navigate to the Edit profile view (My Profile on the left -&gt; Edit profile in the top right corner). Paste the key into the Gpgkey field and click submit.<br><br>
			<p><img src="/img/doc/bottom_bar.png" title = "Click on PGP/GPG key to download the key."/></p><br></li>
			<li><em>Turning Auto-alerts on:</em> Turning auto-alerts on will allow the system to send you e-mail notifications about any new public events entered into the system by other users and private events added by members of your organisation. To turn this on, navigate to the Edit profile view (My profile on the left navigation menu -&gt; Edit profile in the top right corner). Tick the auto-alert checkbox and click submit to enable this feature.<br>
			<p><img src="/img/doc/" title = "Tick this checkbox to enable auto-alerts."/></p><br></li>
			<li><em>Reviewing the Terms &amp; Conditions:</em> To review the Terms &amp; Conditions or to use the User Guide, use the appropriate button on the left navigation menu. </li><br>
			<li><em>Making sure that compatibility mode is turned off (IE9&amp;IE10):</em>Compatibility mode can cause some elements to appear differently than intended or not appear at all. Make sure you have this option turned off.</li>
		</ul>
	<br><hr/><br>

	<a name ="manage"></a><h3>Managing your account:</h3>
		To alter any details regarding your profile, use the "My Profile" menu button to bring up the profile overview and then click on "Edit Profile" in the right upper corner.<br>
		<ul>
			<p><img src="/img/doc/my_profile.png" style="float:right;" title = "Change any of your profile settings here."/></p><br>
			<li><em>Changing your e-mail address:</em> Your e-mail address serves as both a login name and as a means of communication with other users of the MISP system via the contact reporter feature. To change your e-mail address, just enter the edit profile menu (My profile on the left navigation menu -&gt; Edit profile in the top right corner) and change the field titled Email.</li><br>
			<li><em>Changing the password:</em> As a next step, change the password provided by your administrator to something of your own choosing. Click on My profile on the left navigation menu, under Global Actions, which will bring up the User view. Click on Edit User on the left navigation menu or Edit Profile in the top right corner. This next screen, allows you to edit your details, including your password, by filling out the password field. Keep in mind that the password has to be at least 6 characters long, has to include at least one upper-case and one lower-case character in addition to a digit or a special character. Enter the same password into the confirm password field, before clicking submit to finalise the change.</li><br>
			<li><em>Turning Auto-alerts on:</em> Turning auto-alerts on will allow the system to send you e-mail notifications about any new public events entered into the system by other users and private events added by members of your organisation. To turn this on, navigate to the Edit profile view (My profile on the left navigation menu -&gt; Edit profile in the top right corner). Tick the auto-alert checkbox and click submit to enable this feature.</li><br>
			<li><em>Setting up the GPG Key:</em> In order for the system to be able to encrypt the messages that you send through it, it needs to know your GPG key. You can acquire this by clicking on the PGP/GPG key link at the bottom left of the screen. Copy the entirety of the key and navigate to the Edit profile view (My Profile on the left -&gt; Edit profile in the top right corner). Paste the key into the Gpgkey field and click submit.</li><br>
			<li><em>Requesting a new authentication key:</em> It is possible to make the system generate a new authentication key for you (for example if your previous one gets compromised. This can be accessed by clicking on the My Profile button and then clicking the reset key next to the currently active authentication code. The old code will become invalid when the new key is generated. <br>
			<br><p><img src="/img/doc/reset.png" title = "Clicking on reset will generate a new key for you and invalidate the old one, blocking it from being used."/></p></li>
		</ul>
	<br><hr/><br>

	<a name ="uptodate"></a><h3>Staying up to date:</h3>
		MISP also provides its users with some information about itself and its users through the links provided in the Global Actions menu.<br><br>
        <ul>
			<li><em>News:</em> To read about the news regarding the system itself, click on News on the left menu. This will bring up a list of news items concerning updates and changes to MISP itself.</li><br>
			<li><em>Member statistics:</em> By using the Members List menu button on the left, you can get a quick overview over how many users each organisation has registered on your server, and a histogram, depicting the distribution of attribute types created by each organisation.</li><br>
			<li><em>User Guide:</em> The user guide is also accessible via the Global Actions menu. You can find out more about how to use the system by reading this.</li><br>
			<li><em>Terms &amp; Conditions:</em> It is possible to review the terms &amp; conditions that were shown during the first run of the system by clicking on the terms &amp; conditions link in the Global Actions menu. </li><br>
		</ul>



</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
