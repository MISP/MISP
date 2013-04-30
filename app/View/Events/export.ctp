<div class="event index">
<h2>Export</h2>
<p>Export functionality is designed to automatically generate signatures for intrusion detection systems. To enable signature generation for a given attribute, Signature field of this attribute must be set to Yes.
Note that not all attribute types are applicable for signature generation, currently we only support NIDS signature generation for IP, domains, host names, user agents etc., and hash list generation for MD5/SHA1 values of file artifacts. Support for more attribute types is planned.
<br/>
<p>Simply click on any of the following buttons to download the appropriate data.
<table>
<tr>
<td class="actions" style="text-align:center;">
<ul><li><?php echo $this->Html->link(__('Download all as XML', true), array('action' => 'xml', 'download')); ?></li></ul>
</td>
<td>
Click this to download all events and attributes that you have access to <small>(except file attachments)</small> in a custom XML format.
</td>
</tr>
<tr>
<td class="actions" style="text-align:center;">
<ul><li><?php echo $this->Html->link(__('Download NIDS signatures', true), array('action' => 'nids', 'download')); ?></li></ul>
</td>
<td>
Click this to download all network related attributes that you have access to under the Snort rule format. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported. Administration is able to maintain a whitelist containing host, domain name and IP numbers to exclude from the NIDS export.
</td>
</tr>
<tr>
<td class="actions" style="text-align:center;">
<ul><li><?php echo $this->Html->link(__('Download all MD5 hashes', true), array('action' => 'hids', 'md5','download')); ?> </li></ul>
<ul><li><?php echo $this->Html->link(__('Download all SHA1 hashes', true), array('action' => 'hids', 'sha1','download')); ?> </li></ul>
</td>
<td>
Click on one of these two buttons to download all MD5 or SHA1 checksums contained in file-related attributes. This list can be used to feed forensic software when searching for susipicious files. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported.
</td>
</tr>
</table>
<p>
Click on one of these buttons to download all the attributes with the matching type. This list can be used to feed forensic software when searching for susipicious files. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported.
</p>
<p>
<?php
$i = 0;
foreach ($sigTypes as $sigType):
	echo "<div class=\"actions\" style=\"text-align:center; width: auto; padding: 7px 2px;\">".$this->Html->link(__($sigType, true), array('action' => 'text', 'download' ,$sigType))."</div>";
endforeach;
?>
</p>
</div>

<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>