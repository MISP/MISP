<div class="actions <?php echo $debugMode;?>">
	<ol class="nav nav-list">
			<li><?php echo $this->Html->link('Quick Start', array('controller' => 'pages', 'action' => 'display', 'doc', 'quickstart')); ?></li>
			<li><?php echo $this->Html->link('General Layout', array('controller' => 'pages', 'action' => 'display', 'doc', 'general')); ?></li>
			<li class="active"><?php echo $this->Html->link('General Concepts', array('controller' => 'pages', 'action' => 'display', 'doc', 'concepts')); ?></li>
			<li><?php echo $this->Html->link('User Management and Global actions', array('controller' => 'pages', 'action' => 'display', 'doc', 'user_management')); ?></li>
			<li><?php echo $this->Html->link('Using the system', array('controller' => 'pages', 'action' => 'display', 'doc', 'using_the_system')); ?></li>
			<li><?php echo $this->Html->link('Administration', array('controller' => 'pages', 'action' => 'display', 'doc', 'administration')); ?></li>
			<li><?php echo $this->Html->link('Categories and Types', array('controller' => 'pages', 'action' => 'display', 'doc', 'categories_and_types')); ?></li>
		</ol>
</div>

<div class="index">
<h2><a id="general"></a>General Concepts</h2>
<h3>Admins and Site Admins</h3>
There are two types of admins in MISP: Admins (also refered to as org admins) and Site Admins. Whilst the former can only do some limited administration of users of his/her own organisation, site admins have access to all of the features and data of the system. They are in charge of making sure that the system runs correctly and the maintenance of MISP.
<h3>Background Jobs</h3>
A lot of the heavier tasks are a burden to users, in that their actions can cause long delays (and in some cases timeouts) while the application logic is executing. To alleviate this, long processes have been (if enabled) moved to background jobs, meaning that their execution happens asynchronously in the background, allowing the user to freely interact with the platform whilst the request is being processed.
<h3>MISP Instance</h3>
A MISP instance is an installation of the MISP software and the connected database. All the data visible to the users is stored locally in the database and data that is shareable (based on the distribution settings) can be synchronised with other instances via the Sync actions. The instance that you are reading this manual on will be refered to as "this instance" or "your instance". The instances that your instance synchronises with will be refered to as "remote instances".
<h3>Organisation administrators and Site administrators</h3>
We have two types of administrators, site and organisation admins. The former has access to every administrator feature for all the data located on the system including global features such as the creation and modification of user roles and instance links, whilst organisation admins can administer users, events and logs of their own respective organisations.<br />
<h3>Pivot path</h3>
The (branching) path taken by a user from event to event while following correlation links. This is represented by the branching graph in the event view.
<h3>Pivoting</h3>
The act of navigating from event to event through correlation links.
<h3>Proposals</h3>
Each event can only be directly edited by users of the original creator organisation (and site admins). However, if another organisation would like to amend an event with extra information on an event, or if they'd like to correct a mistake in an attribute, they can create a Proposal. These proposals could then be accepted by the original creator organisation. These proposals can be pulled to another server, allowing users on connected instances to propose changes which then could be accepted by the original creators on another instance (and subsequently pushed back).
<h3>Publishing</h3>
When an event is first created by a user, it is visible to everyone on the instance based on the access rights ("Your organisation only" events will not be visible to users of other organisations), but they will not be synchronised and they won't be exportable. For this, a user with publishing permission of the organisation that created the event has to publish the event. The system will then inform all the users of the instance that are subscribing to e-mail notifications and who have access to view the published event via an e-mail.
<h3>Pull</h3>
Pulling is the process of using the configured sync user on a remote instance to REST GET all of the accessible data (based on the distribution rights) to your instance and store it.
<h3>Push</h3>
Pushing is the process of using a configured instance link to send an event or all accessible events (limited by the distribution rights) through the REST interface to a remote instance.
<h3>Scheduled Tasks</h3>
Certain common tasks can be scheduled for a later execution or for regular recurring executions. These tasks currently include caching all of the export formats, pulling from all eligible instances and pushing to all eligible instances.
<h3>Sync User</h3>
A user of a role that grants sync permissions, these users (and their authentication keys) are used to serve as the points of connection between instances. Events pushed to an instance are pushed to a sync user, who then creates the events on the remote instance. Events pulled are added by the sync user that is used to connect the remote instance to your instance. As an administrator, keep in mind that a sync user needs auth key and publish permissions, has to have undergone the mandatory password change and has to have accepted the Terms of Use in order for the sync to work. Please make sure that all of these steps are taken before attempting to push or pull.
<h3>Synchronisation</h3>
What we call synchronisation is an exchange of data between two (or more) MISP instances through our pull and push mechanisms.
<h3>Tagging</h3>
Users with tagging rights can assigned various dynamically created tags to events, allowing an arbitrary link between events to be created. It is possible to filter events based on these tags and they can also be used to filter events for the automation.
<h3>Templating</h3>
Users with templating rights can create easy to fill forms that help with the event creation process.
</div>
