<div class="event index">
<h2>Export</h2>
<p>To make exports available for automated tools an authentication key is used. This makes it easier for your tools to access the data without further form-based-authentiation.<br/>
<strong>Make sure you keep that key secret as it gives access to the entire database !</strong></p>
<p>Your current key is: <code><?php echo $me['authkey'];?></code>.
You can <?php echo $this->Html->link('reset', array('controller' => 'users', 'action' => 'resetauthkey', 'me'));?> this key.
</p>

<h3>XML Export</h3>
<p>An automatic export of all events and attributes is available under a custom XML format.</p>
<p>You can configure your tools to automatically download the following following file:</p>
<pre><?php echo Configure::read('CyDefSIG.baseurl');?>/events/xml/<?php echo $me['authkey']; ?></pre>
<p></p>

<h3>NIDS Export</h3>
<p>An automatic export of all network related attributes is available under the Snort rule format. Only attributes marked as <em>to IDS</em> are exported.</p>
<p>You can configure your tools to automatically download the following following file:</p>
<pre><?php echo Configure::read('CyDefSIG.baseurl');?>/events/nids/<?php echo $me['authkey']; ?></pre>
<p></p>

<h3>Text Export</h3>
<p>An automatic export of all attributes of a specific type to a plain text file.</p>
<p>You can configure your tools to automatically download the following following files:</p>
<pre>
<?php foreach ($sig_types as $sig_type):?>
<?php echo Configure::read('CyDefSIG.baseurl');?>/events/text/<?php echo $me['authkey']; ?>/<?php echo $sig_type."\n";?>
<?php endforeach;?>
</pre>
<p></p>

<h3>Saved search XML Export</h3>
<p>We plan to make it possible to export data using searchpatterns.<br/>
This would enable you to export:</p>
<ul>
<li>only your own attributes</li>
<li>date ranges</li>
<li>only specific attribute types (domain)</li>
<li>...</li>
</ul>



</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>