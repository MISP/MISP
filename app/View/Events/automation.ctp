<div class="event index">
<h2>Automation</h2>
<p>Automation functionality is designed to automatically generate signatures for intrusion detection systems. To enable signature generation for a given attribute, Signature field of this attribute must be set to Yes.
Note that not all attribute types are applicable for signature generation, currently we only support NIDS signature generation for IP, domains, host names, user agents etc., and hash list generation for MD5/SHA1 values of file artifacts. Support for more attribute types is planned.
To to make this functionality available for automated tools an authentication key is used. This makes it easier for your tools to access the data without further form-based-authentiation.<br/>
<strong>Make sure you keep that key secret as it gives access to the entire database !</strong></p>
<p>Your current key is: <code><?php echo $me['authkey'];?></code>.
You can <?php echo $this->Html->link('reset', array('controller' => 'users', 'action' => 'resetauthkey', 'me'));?> this key.
</p>

<h3>XML Export</h3>
<p>An automatic export of all events and attributes <small>(except file attachments)</small> is available under a custom XML format.</p>
<p>You can configure your tools to automatically download the following file:</p>
<pre><?php echo Configure::read('CyDefSIG.baseurl');?>/events/xml/<?php echo $me['authkey']; ?></pre>
<p>If you only want to fetch a specific event append the eventid number:</p>
<pre><?php echo Configure::read('CyDefSIG.baseurl');?>/events/xml/<?php echo $me['authkey']; ?>/1</pre>
<p>Also check out the <?php echo $this->Html->link(__('User Guide', true), array('controller' => 'pages', 'action' => 'display', 'using_the_system', '#' => 'rest')); ?> to read about the REST API.</p>
<p></p>

<h3>NIDS rules export</h3>
<p>Automatic export of all network related attributes is available under the Snort rule format. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported.</p>
<p>You can configure your tools to automatically download the following file:</p>
<pre><?php echo Configure::read('CyDefSIG.baseurl');?>/events/nids/suricata/<?php echo $me['authkey']."\n"; ?>
<?php echo Configure::read('CyDefSIG.baseurl');?>/events/nids/snort/<?php echo $me['authkey']; ?></pre>
<p></p>
<p>Administration is able to maintain a white-list containing host, domain name and IP numbers to exclude from the NIDS export.</p>

<h3>Hash database export</h3>
<p>Automatic export of MD5/SHA1 checksums contained in file-related attributes. This list can be used to feed forensic software when searching for suspicious files. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported.</p>
<p>You can configure your tools to automatically download the following files:</p>
<h4>md5</h4>
<pre><?php echo Configure::read('CyDefSIG.baseurl');?>/events/hids/md5/<?php echo $me['authkey']; ?></pre>
<h4>sha1</h4>
<pre><?php echo Configure::read('CyDefSIG.baseurl');?>/events/hids/sha1/<?php echo $me['authkey']; ?></pre>
<p></p>

<h3>Text export</h3>
<p>An automatic export of all attributes of a specific type to a plain text file.</p>
<p>You can configure your tools to automatically download the following files:</p>
<pre>
<?php
foreach ($sigTypes as $sigType) {
	echo Configure::read('CyDefSIG.baseurl').'/attributes/text/'.$me['authkey'].'/'.$sigType . "\n";
}
?>
</pre>
<p></p>

<h3>RESTful searches with XML result export</h3>
<p>It is possible to search the database for attributes based on a list of criteria. </p>
<p>To return an event with all of its attributes, relations, shadowAttributes, use the following syntax:</p>
<pre>
<?php
	echo Configure::read('CyDefSIG.baseurl').'/events/restSearch/'.$me['authkey'].'/[value]/[type]/[category]/[org]';
?>
</pre>
<p>To just return a list of attributes, use the following syntax:</p>
<pre>
<?php
	echo Configure::read('CyDefSIG.baseurl').'/attributes/restSearch/'.$me['authkey'].'/[value]/[type]/[category]/[org]';
?>
</pre>
<p>value, type, category and org are optional. It is possible to search for several terms in each category by joining them with the '&amp;&amp;' operator. It is also possible to negate a term with the '!' operator.
For example, in order to search for all attributes created by your organisation that contain 192.168 or 127.0 but not 0.1 and are of the type ip-src use the following syntax:</p>
<pre>
<?php
	echo Configure::read('CyDefSIG.baseurl').'/attributes/restSearch/'.$me['authkey'].'/192.168&&127.0&&!0.1/ip-src/null/' . $me['org'];
?>
</pre>
<p>You can also use search for IP addresses using CIDR. Make sure that you use '|' (pipe) instead of '/' (slashes). See below for an example: </p>
<pre>
<?php
	echo Configure::read('CyDefSIG.baseurl').'/attributes/restSearch/'.$me['authkey'].'/192.168.1.1|16/ip-src/null/' . $me['org'];
?>
</pre>

<h3>Export attributes of event with specified type as XML</h3>
<p>If you want to export all attributes of a pre-defined type that belong to an event, use the following syntax:</p>
<pre>
<?php
	echo Configure::read('CyDefSIG.baseurl').'/attributes/returnAttributes/'.$me['authkey'].'/[id]/[type]/[sigOnly]';
?>
</pre>
<p>sigOnly is an optional flag that will block all attributes from being exported that don't have the IDS flag turned on.
It is possible to search for several types with the '&amp;&amp;' operator and to exclude values with the '!' operator.
For example, to get all IDS signature attributes of type md5 and sha256, but not filename|md5 and filename|sha256 from event 25, use the following: </p>
<pre>
<?php
	echo Configure::read('CyDefSIG.baseurl').'/attributes/returnAttributes/'.$me['authkey'].'/25/md5&&sha256&&!filename/true';
?>
</pre>

<h3>Download attachment or malware sample</h3>
<p>If you know the attribute ID of a malware-sample or an attachment, you can download it with the following syntax:</p>
<pre>
<?php
	echo Configure::read('CyDefSIG.baseurl').'/attributes/downloadAttachment/'.$me['authkey'].'/[Attribute_id]';
?>
</pre>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'automation'));
?>
