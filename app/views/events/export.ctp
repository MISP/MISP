<div class="event index">
<h2>Export</h2>
<p>To make exports available for automated tools an authentication key is used. This makes it easier for your tools to access the data without further form-based-authentiation.<br/>
<strong>Make sure you keep that key secret as it gives access to the entire database !</strong></p>
<p>Your current key is: <code><?php echo $me['authkey'];?></code>. 
You can <?php echo $this->Html->link('reset', array('controller' => 'users', 'action' => 'resetauthkey', 'me'));?> this key.
</p>

<h3>XML Export</h3>
<p>An automatic export of all events and signatures is available under a custom XML format.</p>
<p>You can configure your tools to automatically download the following following file:</p>
<pre>https://sig.cyber-defence.be/events/xml/<?php echo $me['authkey']; ?></pre>
<p></p>

<h3>NIDS Export</h3>
<p>An automatic export of all network related signatures is available under the Snort rule format.</p>
<p>You can configure your tools to automatically download the following following file:</p>
<pre>https://sig.cyber-defence.be/events/nids/<?php echo $me['authkey']; ?></pre>
<p></p>

<h3>Text Export</h3>
<p>An automatic export of all signatures of a specific type to a plain text file.</p>
<p>You can configure your tools to automatically download the following following file:</p>
<pre>
<?php foreach ($sig_types as $sig_type):?>
https://sig.cyber-defence.be/events/text/<?php echo $me['authkey']; ?>/<?php echo $sig_type."\n";?>
<?php endforeach;?>
</pre>
<p></p>

<h3>Saved search XML Export</h3>
<p>We plan to make it possible to export data using searchpatterns.<br/>
This would enable you to export:</p>
<ul>
<li>only your own signatures</li>
<li>date ranges</li>
<li>only specific signature types (domain)</li>
<li>...</li>
</ul>



</div>
<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>
		<?php echo $this->element('actions_menu'); ?>

	</ul>
</div>