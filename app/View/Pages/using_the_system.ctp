<div class="index">
<p><b>Table of contents</b><br>
1. <?php echo $this->Html->link(__('General Layout', true), array('controller' => 'pages', 'action' => 'display', 'documentation')); ?><br>
2. <?php echo $this->Html->link(__('User Management and Global actions', true), array('controller' => 'pages', 'action' => 'display', 'user_management')); ?><br>
3. <?php echo $this->Html->link(__('Using the system', true), array('controller' => 'pages', 'action' => 'display', 'using_the_system')); ?><br>
<ul>
	<li>a. <a href="#create">Creating an event</a></li>
	<li>b. <a href="#browsing_events">Browsing past events</a></li>
	<li>c. <a href="#update_events">Updating and modifying events</a></li>
	<li>d. <a href="#contact">Contacting the publisher</a></li>
	<li>e. <a href="#export">Exporting data</a></li>
</ul>
4. <?php echo $this->Html->link(__('Administration', true), array('controller' => 'pages', 'action' => 'display', 'administration')); ?><br>
5. <?php echo $this->Html->link(__('Categories and Types', true), array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?></p>
<hr/><br>
<h2>Using the system:</h2>
<a name ="create"></a><h3>Creating an event:</h3>
The process of entering an event can be split into 3 phases, the creation of the event itself, populating it with attributes and attachments and finally publishing it.<br><br>
    During this first step, you will be create a basic event without any actual attributes, but storing general information such as a description, time and risk level of the incident. To start creating the event, click on the New Event button on the left and fill out the form you are presented with. The following fields need to be filled out:<br><br>
	<ul>
		<p><img src="/img/doc/add_event.png" style="float:right;" title = "Fill this form out to create a skeleton event, before proceeding to populate it with attributes and attachments."/></p><br>
		<li><em>Date:</em> The date when the incident has happened.</li><br>
		<li><em>Distribution:</em> This setting controls, who will be able to see this event once it becomes published. Apart from being able to set which users on your server are allowed to see the event, this also controls whether the event will be synchronised to other servers or not. The following options are available:</li><br>
		<ul>
			<li><i>Org:</i> This setting will only allow members of your organisation on your server to see it.</li><br>
			<li><i>Community:</i> Users that are part of your MISP community will be able to see the event. This includes your own organisation, organisations on your MISP server and organisations running MISP servers that synchronise with your server. Any other organisations connected to such linked servers will be restricted from seeing the event.</li><br>
			<li><i>All:</i> This will share the event with all trusted MISP communities, meaning all the members of every community that is connected to your server.</li><br>
		</ul>
		<li><em>Risk:</em> This field indicates the risk level of the event. Incidents can be categorised into three different threat categories (low, medium, high). This field can alternatively be left as undefined. The 3 options are:</li><br>
		<ul>
			<li><i>Low:</i> General mass malware.</li><br>
			<li><i>Medium:</i> Advanced Persistent Threats (APT)</li><br>
			<li><i>High:</i> Sophisticated APTs and 0day attacks.</li><br>
			<li><i>Info:</i> The info field, where the malware/incident can get a brief description starting with the internal reference. This field should be as brief and concise as possible, the more detailed description happens through attributes in the next stage of the event's creation.</li><br></ul>
		</ul>
		<li><em>GFI Sandbox:</em> It is possible to upload the exported .zip file from GFI sandbox with the help of this tool. These will be dissected by the MISP and a list of attributes and attachments will automatically be generated from the .zip file. Whilst this does most of the work needed to be done in the second step of the event's creation, it is important to manually look over all the data that is being entered. </li><br>
	</ul>	
<br><hr/></br>
<a name ="create_attribute"></a><h3>Add attributes to the event:</h3>
The second step of creating an event is to populate it with attributes and attachments. In addition to being able to import the attributes and attachments from GFI, it is also possible to manually add attributes and attachments to an event, by using the two appropriate buttons on the event's page. Let's look at adding attributes first.<br>
When clicking on the add attribute button, you will have to fill out a form with all the data about the attribute. The following fields need to be filled out:<br>
<ul>
	<p><img src="/img/doc/add_attribute.png" style="float:right;" title = "This form allows you to add attributes."/></p><br>
	<li><em>Category:</em> This drop-down menu explains the category of the attribute, meaning what aspect of the malware this attribute is describing. This could mean the persistence mechanisms of the malware or network activity, etc. For a list of valid categories, <?php echo $this->Html->link(__('click here', true), array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?></li><br>
       <li><em>Type:</em> Whilst categories determine what aspect of an event they are describing, the Type explains by what means that aspect is being described. As an example, the source IP address of an attack, a source e-mail address or a file sent through an attachment can all describe the payload delivery of a malware. These would be the types of attributes with the category of payload deliver. For an explanation of what each of the types looks like together with the valid combinations of categories and types, <?php echo $this->Html->link(__('click here', true), array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?>.</li><br>
       <li><em>Distribution:</em> This drop-down list allows you to control who will be able to see this attribute, independently from its event's distribution settings.</li><br>
		<ul>
               <li><i>Org:</i> This setting will only allow members of your organisation on your server to see it.</li><br>
               <li><i>Community:</i> Users that are part of your MISP community will be able to see the event. This includes your own organisation, organisations on your MISP server and organisations running MISP servers that synchronise with your server. Any other organisations connected to such linked servers will be restricted from seeing the event.</li><br>
               <li><i>All:</i> This will share the event with all trusted MISP communities, meaning all the members of every community that is connected to your server.</li><br>
		</ul>
       <li><em>IDS Signature:</em> This option allows the attribute to be used as an IDS signature when exporting the NIDS data, unless it is being overruled by the white-list. For more information about the whitelist, head over to the <?php echo $this->Html->link(__('administration', true), array('controller' => 'pages', 'action' => 'display', 'administration')); ?> section and scroll down to the whitelist sub-section.</li><br>
       <li><em>Value:</em> The actual value of the attribute, enter data about the value based on what is valid for the chosen attribute type. For example, for an attribute of type ip-src (source IP address), 11.11.11.11 would be a valid value. For more information on types and values, <?php echo $this->Html->link(__('click here', true), array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?>.</li><br>
       <li><em>Batch import:</em> If there are several attributes of the same type to enter (such as a list of IP addresses, it is possible to enter them all into the same value-field, separated by a line break between each line. This will allow the system to create separate lines for the each attribute. </li><br>
</ul>		
<br><hr/><br>
<h3>Add attachments to the event:</h3>
You can also upload attachments, such as the malware itself, report files from external analysis or simply artifacts dropped by the malware. Clicking on the add attachment button brings up a form that allows you to quickly attach a file to the event. The following fields need to be filled out:<br><br>
<p><img src="/img/doc/add_attachment.png" title = "Point the uploader to the file you want to upload. Make sure to mark it as malware if the uploaded file is harmful, that way it will be neutralised."/></p><br>
<ul>
    <li><em>Category:</em> The category is the same as with the attributes, it answers the question of what the uploaded file is meant to describe.</li><br>
    <li><em>Upload field:</em> By hitting browse, you can browse your file system and point the uploader to the file that you want to attach to the attribute. This will then be uploaded when the upload button is pushed.</li><br>
    <li><em>Malware:</em> This check-box marks the file as malware and as such it will be zipped and passworded, to protect the users of the system from accidentally downloading and executing the file. Make sure to tick this if you suspect that the filed is infected, before uploading it.</li><br>
    <li><em>Private:</em> This drop-down menu controls who the attachment will be shared as.</li><br>
	<ul>
		<li><i>Org:</i> This setting will only allow members of your organisation on your server to see it.</li><br>
           <li><i>Community:</i> Users that are part of your MISP community will be able to see the event. This includes your own organisation, organisations on your MISP server and organisations running MISP servers that synchronise with your server. Any other organisations connected to such linked servers will be restricted from seeing the event.</li><br>
           <li><i>All:</i> This will share the event with all trusted MISP communities, meaning all the members of every community that is connected to your server.</li><br>
	</ul>
</ul>
<br><hr/><br>
<h3>Publish an event:</h3>
<p><img src="/img/doc/publish.png" style="float:right;" title = "Only use publish (no email) for minor changes such as the correction of typos."/></p><br>
Once all the attributes and attachments that you want to include with the event are uploaded / set, it is time to finalise its creation by publishing the event (click on publish event in the event view). This will alert the eligible users of it (based on the private-controls of the event and its attributes/attachments and whether they have auto-alert turned on), push the event to servers that your server connects to if allowed (private needs to be set to all) and readies the network related attributes for NIDS signature creation (through the NIDS signature export feature, for more information, go to the export section.).<br><br>
There is an alternate way of publishing an event without alerting any other users, by using the "publish (no email)" button. This should only be used for minor edits (such as correcting a typo). <br>
<br><hr/><br>
<a name ="browsing_events"></a><h2>Browsing past events:</h2>
The MISP interface allows the user to have an overview over or to search for events and attributes of events that are already stored in the system in various ways.<br><br>
<h3>To list all events:</h3>
On the left menu bar, the option "List events" will generate a list of the last 60 events. While the attributes themselves aren't shown in this view, the following pieces of information can be seen:<br><br>
<img src="/img/doc/list_events2.png" title = "This is the list of events in the system. Use the buttons to the right to alter or view any of the events."/>
    <ul>
		<li><em>ID:</em> The event's ID number, assigned by the system when the event was first entered (or in the case of an event that was synchronized, when it was first copied over - more on synchronisation in chapter xy)</li><br>
		<li><em>Email:</em> The e-mail address of the event's reporter.</li><br>
		<li><em>Date:</em> The date of the attack.</li><br>
		<li><em>Risk:</em> The risk level of the attack, the following levels are possible:</li><br>
		<ul>
            <li><em>Low:</em> General Malware</li>
            <li><em>Medium:</em> Advanced Persistent Threats (APTs)</li>
            <li><em>High:</em> Sophisticated APTs and 0day exploits</li>
			<li><em>Undefined:</em> This field can be left undefined and edited at a later date.</li><br>
		</ul>
        <li><em>Info:</em> A short description of the event, starting with an internal reference number.</li><br>
        <li><em>Distribution:</em> This field indicates what the sharing privileges of the event are. Org means that the event is only visible to the posting organisation, server only means that the entire server can see it, no matter the organisation and if the distribution field of an event is flagged all then it can be pushed and pulled freely to trusted communities (to all members of communities that are connected to the home server).</li><br>
        <li><em>Actions:</em> The controls that the user has to view or modify the event. The possible actions that are available (depending on user privileges - <?php echo $this->Html->link(__('click here', true), array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?> to find out more about privileges):</li><br>
		<ul>
            <li><em>Publish:</em> Publishing an event will have several effects: The system will e-mail all eligible users that have auto-alert turned on (and having the needed privileges for the event, depending on its private classification) with a description of your newly published event, it will be flagged as published and it will be pushed to all eligible servers (to read more about synchronisation between servers, have a look at the <?php echo $this->Html->link(__('administration', true), array('controller' => 'pages', 'action' => 'display', 'administration')); ?> section).</li>
            <li><em>Edit:</em> Clicking on the edit button will bring up the same same screen as the one used for creating new events, with the exception that all fields come filled out with the data of the event that is being edited. For more information on this view, refer to the section on <a href="#create">creating an event</a>.</li>
            <li><em>Delete:</em> The system will prompt you before erasing the unwanted event.</li>
            <li><em>View:</em> Will bring up the event view, which besides the basic information contained in the event list, will also include the following:<br><br>
			<img src="/img/doc/event_detail.png" title = "This view includes the basic information about an event, a link to related events, all attributes and attachments with tools to modify or delete them and extra functions for publishing the event or getting in touch with the event's reporter."/></li><br>
		</ul>
		<li><em>List of related events:</em> Events can be related by having one or more attributes that are exact matches. For example, if two events both contain a source IP attribute of 11.11.11.11 then they are related. The list of events that are related the currently shown one, are listed under "Related Events", as links (titled the related event's date and ID number) to the events themselves.</li><br>
        <li><em>Attributes:</em> A list of all attributes attached to the event, including its category, type, value, whether the attribute in itself is related to another event, whether the flag signalling that the attribute can be turned into an IDS signature is on, and a field showing the current privacy setting of the attribute.Attributes can also be modified or deleted via the 3 buttons at the end of each line.<br><br>
		Using the modify button will bring up the attribute creation view, with all data filled out with the attribute's currently stored data.</li><br>
	</ul>	
<br><hr/><br>
<h3>Listing all attributes:</h3>
	Apart from having a list of all the events, it is also possible to get a list of all the stored attributes in the system by clicking on the list attributes button. The produced list of attributes will include the followings fields:<br><br>
	<img src="/img/doc/list_attributes2.png" title = "Use the buttons to the right to view the event that this attribute belongs to or to modify/delete the attribute."/><br><br>
	<ul>
        <li><em>Event:</em> This is the ID number of the event that the attribute is tied to.</li><br>
        <li><em>Category:</em> The category of the attribute, showing what the attribute describes (for example the malware's payload). For more information on categories, go to section xy</li><br>
        <li><em>Type:</em> The type of the value contained in the attribute (for example a source IP address). For more information on types, go to section xy</li><br>
        <li><em>Value:</em> The actual value of the attribute, describing an aspect, defined by the category and type fields of the malware (for example 11.11.11.11).</li><br>
        <li><em>Signature:</em> Shows whether the attribute has been flagged for NIDS signature generation or not.</li><br>
        <li><em>Actions:</em> A set of buttons that allow you to view the event that the attribute is tied to, to edit the attribute (using the same view as what is used to set up attributes, but filled out with the attribute's current data) and a delete button. </li><br>
    </ul>
<br><hr/><br>
<h3>Searching for attributes:</h3>
Apart from being able to list all events, it is also possible to search for data contained in the value field of an attribute, by clicking on the "Search Attributes" button.<br><br>
<img src="/img/doc/search_attribute.png" title = "You can search for attributes by searching for a phrase contained in its value. Narrow your search down by selecting a type and/or a category which the event has to belong to."/><br><br>
This will bring up a form that lets you enter a search string that will be compared to the values of all attributes, along with options to narrow down the search based on category and type. The entered search string has to be an exact match with (the sub-string of) a value.<br><br>
The list generated by the search will look exactly the same as listing all attributes, except that only the attributes that matched the search criteria will be listed (to find out more about the list attributes view, <?php echo $this->Html->link(__('click here', true), array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?>.).<br>
<br><img src="/img/doc/search_attribute_result.png" title = "You can view the event that an attribute belongs to with the view button, or you can edit/delete the attribute via the buttons on the right."/><br>
<br><hr/><br>
<a name ="update_events"></a><h2>Updating and modifying events and attributes:</h2>
Every event and attribute can easily be edited. First of all it is important to find the event or attribute that is to be edited, using any of the methods mentioned in the section on <a href="#browsing_events">browsing past events</a>.<br><br>
Once it is found, the edit button (whether it be under actions when events/attributes get listed or simply on the event view) will bring up the same screen as what is used to create the entry of the same type (for an event it would be the event screen as <a href="#create">seen here</a>, for an attribute the attribute screen as <a href="#create_attribute">described here</a>).<br><br>
Keep in mind that editing any event (either directly or indirectly through an attribute) will unpublish it, meaning that you'll have to publish it (through the event view) again once you are done.<br><br>
<br><img src="/img/doc/edit_event.png" title = "Just alter any of the fields and click submit to change the event."/><br>
 <br><hr/><br>   
<a name ="contact"></a><h2>Contacting the publisher:</h2>
To get in touch with the reporter of a previously registered event, just find the event for which you would like to contact the reporter by either finding it on the list of events, by finding it through one of its attributes or by finding it through a related event.<br><br>
Once the event is found and the event view opened, click the button titled "Contact Reporter". This will bring up a view where you can enter your message that is to be e-mailed to the reporting organisation or the reporter himself. Along with your message, the detailed information about the event in question will be included in the e-mail.<br><br>
<br><img src="/img/doc/contact_reporter.png" title = "Enter your message to the reporter and choose whether his/her entire organisation should get the message or not by ticking the check-box."/><br><br>
By default, the message will be sent to every member of the organisation that posted the event in the first place, but if you tick the check-box below the message field before sending the mail, only the person that reported the event will get e-mailed. <br>
<br><hr/><br> 
<a name ="export"></a><h2>Exporting data:</h2>
It is possible to quickly and conveniently export the data contained within the system using the export features located in the main menu on the left. There are various sets of data that can be exported, by using the authentication key provided by the system (also shown on the export page). If for whatever reason you would need to invalidate your current key and get a new one instead (for example due to the old one becoming compromise) just hit the reset link next to the authentication key in the export view or in your "my profile" view.<br><br>
The following types of export are possible:<br><br>
    <h3>XML export:</h3>
		Exports all attributes and the event data of every single event in the database in the XML format. The usage is:<br><br><i>&lt;server>/events/xml/&lt;authentication_key></i><br><br>
		In order to export the data about a single event and its attributes, use the following syntax:<br><br>
		<i>&lt;server>/events/xml/&lt;authentication_key>/&lt;EventID></i><br><br>
    <h3>NIDS export:</h3>
		This allows the user to export all network related attributes under the Snort format. The attributes have to belong to a published event and they have to have IDS signature generation enabled. The types that will be used when creating the export are: email-dst, ip-src, ip-dst, snort, url, domain. The usage is as follows:<br><br><i>&lt;server>/events/nids/&lt;authentication_key></i><br><br>
    <h3>Hash database export:</h3>
		There are two hash formats (sha1 and md5) in which all filenames stored in the system can be exported. Events need to be published and the IDS Signature field needs to be turned on for this export. The usage is as follows:<br><br>
		For MD5: <i>&lt;server>events/hids_md5/&lt;authentication_key></i><br><br>
		For SHA1: <i>&lt;server>events/hids_sha1/&lt;authentication_key></i><br><br>
    <h3>Text export:</h3>
        It is also possible to export a list of all attributes that match a specific type into a plain text file. The format to do this is:<br><br>
		<i>&lt;server>/events/text/&lt;authentication_key>/&lt;type></i><br><br>
		Type could be any valid type (as according to section 10), for example md5, ip-src or comment.

</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

<script type="text/javascript" src="/js/jquery-toc.js">
</script>



