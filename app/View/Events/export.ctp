<div class="event index">
	<h2>Export</h2>
	<p>Export functionality is designed to automatically generate signatures for intrusion detection systems. To enable signature generation for a given attribute, Signature field of this attribute must be set to Yes.
	Note that not all attribute types are applicable for signature generation, currently we only support NIDS signature generation for IP, domains, host names, user agents etc., and hash list generation for MD5/SHA1 values of file artifacts. Support for more attribute types is planned.
	<br/>
	<p>Simply click on any of the following buttons to download the appropriate data.</p>
	<?php $i = 0;?>
	<table class="table table-striped table-hover table-condensed">
		<tr>
			<th style="text-align:center;">Type</th>
			<th style="text-align:center;">Last Update</th>
			<th style="text-align:center;">Description</th>
			<th style="text-align:center;">Progress</th>
			<th style="text-align:center;">Actions</th>
		</tr>
		<?php foreach ($export_types as $type): ?>
			<tr>
				<td class="short"><?php echo $type['type']; ?></td>
				<td class="short" style="color:red;"><?php echo $type['lastModified']; ?></td>
				<td><?php echo $type['description']; ?></td>
				<td style="width:150px;">
							<div class="progress progress-striped active" style="margin-bottom: 0px;">
				  <div id="bar<?php echo $i; ?>" class="bar" style="width: <?php echo 0; ?>%;">
				 	 <?php 
				 	 	if (1 > 0 && 0 < 100) echo 0 . '%'; 
				 	 	if (0 == 100) echo 'Completed.';
				 	 ?>
				  </div>
				</div>
					<script type="text/javascript">
					setInterval(function(){
						$.getJSON('/jobs/getGenerateCorrelationProgress/<?php echo h($item['Job']['id']); ?>', function(data) {
							var x = document.getElementById("bar<?php echo h($item['Job']['id']); ?>"); 
							x.style.width = data+"%";
							if (data > 0 && data < 100) {
								x.innerHTML = data + "%";
							}
							if (data == 100) {
								x.innerHTML = "Completed.";
							}
						});
						}, 1000);
	
					</script>
					<?php $i++; ?>
				</td>
				<td style="width:150px;">
					<?php echo $this->Html->link('Download', array('action' => 'xml', 'download'), array('class' => 'btn btn-inverse toggle-left btn.active qet')); 
					echo $this->Html->link('Generate', array('action' => 'cacheXML'), array('class' => 'btn btn-inverse toggle-right btn.active qet')); ?>
				</td>
			</tr>
		<?php endforeach; ?>
	</table>
	<p>
	Click on one of these buttons to download all the attributes with the matching type. This list can be used to feed forensic software when searching for susipicious files. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported.
	</p>

	<ul class="inline">
	<?php
	foreach ($sigTypes as $sigType): ?>
		<li class="actions" style="text-align:center; width: auto; padding: 7px 2px;">
		<?php echo $this->Html->link($sigType, array('action' => 'text', 'download' ,$sigType), array('class' => 'btn')) ?>
		</li>
	<?php endforeach; ?>
	</ul>

</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'event-collection', 'menuItem' => 'export'));
?>
