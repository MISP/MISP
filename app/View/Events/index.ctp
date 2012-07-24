<?php
$button_add_status = $isAclAdd ? 'button_on':'button_off';
$button_modify_status = $isAclModify ? 'button_on':'button_off';
$button_publish_status = $isAclPublish ? 'button_on':'button_off';
$buttonCounter = 0;
?>
<div class="events index">
	<h2>Events</h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<th><?php echo $this->Paginator->sort('user_id', 'Email');?></th>
			<?php endif; ?>
			<th><?php echo $this->Paginator->sort('date');?></th>
	        <th<?php echo ' title="' . $event_descriptions['risk']['desc'] . '"';?>><?php echo $this->Paginator->sort('risk');?></th>
			<th><?php echo $this->Paginator->sort('info');?></th>
			<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
			<th<?php echo ' title="' . $event_descriptions['private']['desc'] . '"';?>><?php echo $this->Paginator->sort('private');?></th>
			<?php endif; ?>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
	foreach ($events as $event):
	?>
	<tr>
		<td class="short">
		<?php echo $this->Html->link($event['Event']['id'], array('controller' => 'events', 'action' => 'view', $event['Event']['id'])); ?>
		&nbsp;</td>
		<?php if ('true' == Configure::read('CyDefSIG.showorg') || $isAdmin): ?>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true) ;?>';">
		<?php echo h($event['Event']['org']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true) ;?>';">
		<?php echo h($event['User']['email']); ?>&nbsp;</td>
		<?php endif; ?>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true) ;?>';">
		<?php echo $event['Event']['date']; ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true) ;?>';">
		<?php echo $event['Event']['risk']; ?>&nbsp;</td>
		<td onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true) ;?>';">
		<?php echo nl2br(h($event['Event']['info'])); ?>&nbsp;</td>
		<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('action' => 'view', $event['Event']['id']), true) ;?>';">
		<?php echo ($event['Event']['private'])? 'Private' : ''; ?>&nbsp;</td>
		<?php endif; ?>
		<td class="actions">
			<?php
			if (0 == $event['Event']['published'] && ($isAdmin || $event['Event']['org'] == $me['org']))
			    if ($isAclPublish || $event['Event']['user_id'] == $me['id']) echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), array('action' => 'alert', $event['Event']['id']), 'Are you sure this event is complete and everyone should be informed?');
			    else echo $this->Html->link('Publish Event', array('id' =>$button_publish_status.$buttonCounter++,'class' => $button_publish_status, 'action' => 'alert', $event['Event']['id']), array('id' =>$button_publish_status.$buttonCounter++,'class' => $button_publish_status, 'action' => 'alert', $event['Event']['id']));
			elseif (0 == $event['Event']['published']) echo 'Not published';
			?>
			<?php
			if ($isAdmin || $event['Event']['org'] == $me['org']) {
  			   echo $this->Html->link(__('Edit', true), array('action' => 'edit', $event['Event']['id']), $isAclModify||($event['Event']['user_id'] == $me['id']) ? null:array('id' => $button_modify_status.$buttonCounter++, 'class' => $button_modify_status));
  			   if ($isAclModify || $event['Event']['user_id'] == $me['id']) echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id']));
  				else echo $this->Html->link(__('Delete'), array('action' => 'delete', $event['Event']['id']), array('id' =>$button_modify_status.$buttonCounter++,'class' => $button_modify_status));
			}
			?>
			<?php echo $this->Html->link(__('View', true), array('controller' => 'attributes', 'action' => 'event', $event['Event']['id'])); ?>
		</td>
	</tr>
<?php endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Paginator->counter(array(
	'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
	));
	?>	</p>

	<div class="paging">
		<?php echo $this->Paginator->prev('<< ' . __('previous', true), array(), null, array('class'=>'disabled'));?>
	 | 	<?php echo $this->Paginator->numbers();?>
 |
		<?php echo $this->Paginator->next(__('next', true) . ' >>', array(), null, array('class' => 'disabled'));?>
	</div>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
<!--?php $javascript->link('deactivateButtons.js', false); ?-->
<!--script type="text/javascript" src="deactivateButtons.js"></script-->
<script type="text/javascript">
$('#button_off').click(function() {
	return false;
});
$('#button_off0').click(function() {
	return false;
});
$('#button_off1').click(function() {
	return false;
});
$('#button_off2').click(function() {
	return false;
});
$('#button_off3').click(function() {
	return false;
});
$('#button_off4').click(function() {
	return false;
});
$('#button_off5').click(function() {
	return false;
});
$('#button_off6').click(function() {
	return false;
});
$('#button_off7').click(function() {
	return false;
});
$('#button_off8').click(function() {
	return false;
});
$('#button_off9').click(function() {
	return false;
});
$('#button_off10').click(function() {
	return false;
});
$('#button_off11').click(function() {
	return false;
});
$('#button_off12').click(function() {
	return false;
});
$('#button_off13').click(function() {
	return false;
});
$('#button_off14').click(function() {
	return false;
});
$('#button_off15').click(function() {
	return false;
});
$('#button_off16').click(function() {
	return false;
});
$('#button_off17').click(function() {
	return false;
});
$('#button_off10').click(function() {
	return false;
});
$('#button_off19').click(function() {
	return false;
});
$('#button_off20').click(function() {
	return false;
});
$('#button_off21').click(function() {
	return false;
});
$('#button_off22').click(function() {
	return false;
});
$('#button_off23').click(function() {
	return false;
});
$('#button_off24').click(function() {
	return false;
});
$('#button_off25').click(function() {
	return false;
});
$('#button_off26').click(function() {
	return false;
});
$('#button_off27').click(function() {
	return false;
});
$('#button_off20').click(function() {
	return false;
});
$('#button_off29').click(function() {
	return false;
});
$('#button_off30').click(function() {
	return false;
});
$('#button_off31').click(function() {
	return false;
});
$('#button_off32').click(function() {
	return false;
});
$('#button_off33').click(function() {
	return false;
});
$('#button_off34').click(function() {
	return false;
});
$('#button_off35').click(function() {
	return false;
});
$('#button_off36').click(function() {
	return false;
});
$('#button_off37').click(function() {
	return false;
});
$('#button_off30').click(function() {
	return false;
});
$('#button_off39').click(function() {
	return false;
});
$('#button_off40').click(function() {
	return false;
});
$('#button_off41').click(function() {
	return false;
});
$('#button_off42').click(function() {
	return false;
});
$('#button_off43').click(function() {
	return false;
});
$('#button_off44').click(function() {
	return false;
});
$('#button_off45').click(function() {
	return false;
});
$('#button_off46').click(function() {
	return false;
});
$('#button_off47').click(function() {
	return false;
});
$('#button_off40').click(function() {
	return false;
});
$('#button_off49').click(function() {
	return false;
});
$('#button_off50').click(function() {
	return false;
});
$('#button_off51').click(function() {
	return false;
});only in
$('#button_off52').click(function() {
	return false;
});
$('#button_off53').click(function() {
	return false;
});
$('#button_off54').click(function() {
	return false;
});
$('#button_off55').click(function() {
	return false;
});
$('#button_off56').click(function() {
	return false;
});
$('#button_off57').click(function() {
	return false;
});
$('#button_off50').click(function() {
	return false;
});
$('#button_off59').click(function() {
	return false;
});
$('#button_off60').click(function() {
	return false;
});
$('#button_off61').click(function() {
	return false;
});
$('#button_off62').click(function() {
	return false;
});
$('#button_off63').click(function() {
	return false;
});
$('#button_off64').click(function() {
	return false;
});
$('#button_off65').click(function() {
	return false;
});
$('#button_off66').click(function() {
	return false;
});
$('#button_off67').click(function() {
	return false;
});
$('#button_off60').click(function() {
	return false;
});
$('#button_off69').click(function() {
	return false;
});
$('#button_off70').click(function() {
	return false;
});
$('#button_off71').click(function() {
	return false;
});
$('#button_off72').click(function() {
	return false;
});
$('#button_off73').click(function() {
	return false;
});
$('#button_off74').click(function() {
	return false;
});
$('#button_off75').click(function() {
	return false;
});
$('#button_off76').click(function() {
	return false;
});
$('#button_off77').click(function() {
	return false;
});
$('#button_off70').click(function() {
	return false;
});
$('#button_off79').click(function() {
	return false;
});
$('#button_off80').click(function() {
	return false;
});
$('#button_off81').click(function() {
	return false;
});
$('#button_off82').click(function() {
	return false;
});
$('#button_off83').click(function() {
	return false;
});
$('#button_off84').click(function() {
	return false;
});
$('#button_off85').click(function() {
	return false;
});
$('#button_off86').click(function() {
	return false;
});
$('#button_off87').click(function() {
	return false;
});
$('#button_off80').click(function() {
	return false;
});
$('#button_off89').click(function() {
	return false;
});
$('#button_off90').click(function() {
	return false;
});
$('#button_off91').click(function() {
	return false;
});
$('#button_off92').click(function() {
	return false;
});
$('#button_off93').click(function() {
	return false;
});
$('#button_off94').click(function() {
	return false;
});
$('#button_off95').click(function() {
	return false;
});
$('#button_off96').click(function() {
	return false;
});
$('#button_off97').click(function() {
	return false;
});
$('#button_off90').click(function() {
	return false;
});
$('#button_off99').click(function() {
	return false;
});
$('#button_off100').click(function() {
	return false;
});
$('#button_off101').click(function() {
	return false;
});
$('#button_off102').click(function() {
	return false;
});
$('#button_off103').click(function() {
	return false;
});
$('#button_off104').click(function() {
	return false;
});
$('#button_off105').click(function() {
	return false;
});
$('#button_off106').click(function() {
	return false;
});
$('#button_off107').click(function() {
	return false;
});
$('#button_off100').click(function() {
	return false;
});
$('#button_off109').click(function() {
	return false;
});
$('#button_off110').click(function() {
	return false;
});
$('#button_off111').click(function() {
	return false;
});
$('#button_off112').click(function() {
	return false;
});
$('#button_off113').click(function() {
	return false;
});
$('#button_off114').click(function() {
	return false;
});
$('#button_off115').click(function() {
	return false;
});
$('#button_off116').click(function() {
	return false;
});
$('#button_off117').click(function() {
	return false;
});
$('#button_off110').click(function() {
	return false;
});
$('#button_off119').click(function() {
	return false;
});
$('#button_off120').click(function() {
	return false;
});
$('#button_off121').click(function() {
	return false;
});
$('#button_off122').click(function() {
	return false;
});
$('#button_off123').click(function() {
	return false;
});
$('#button_off124').click(function() {
	return false;
});
$('#button_off125').click(function() {
	return false;
});
$('#button_off126').click(function() {
	return false;
});
$('#button_off127').click(function() {
	return false;
});
$('#button_off120').click(function() {
	return false;
});
$('#button_off129').click(function() {
	return false;
});
$('#button_off130').click(function() {
	return false;
});
$('#button_off131').click(function() {
	return false;
});
$('#button_off132').click(function() {
	return false;
});
$('#button_off133').click(function() {
	return false;
});
$('#button_off134').click(function() {
	return false;
});
$('#button_off135').click(function() {
	return false;
});
$('#button_off136').click(function() {
	return false;
});
$('#button_off137').click(function() {
	return false;
});
$('#button_off130').click(function() {
	return false;
});
$('#button_off139').click(function() {
	return false;
});
$('#button_off140').click(function() {
	return false;
});
$('#button_off141').click(function() {
	return false;
});
$('#button_off142').click(function() {
	return false;
});
$('#button_off143').click(function() {
	return false;
});
$('#button_off144').click(function() {
	return false;
});
$('#button_off145').click(function() {
	return false;
});
$('#button_off146').click(function() {
	return false;
});
$('#button_off147').click(function() {
	return false;
});
$('#button_off140').click(function() {
	return false;
});
$('#button_off149').click(function() {
	return false;
});
$('#button_off150').click(function() {
	return false;
});
$('#button_off151').click(function() {
	return false;
});
$('#button_off152').click(function() {
	return false;
});
$('#button_off153').click(function() {
	return false;
});
$('#button_off154').click(function() {
	return false;
});
$('#button_off155').click(function() {
	return false;
});
$('#button_off156').click(function() {
	return false;
});
$('#button_off157').click(function() {
	return false;
});
$('#button_off150').click(function() {
	return false;
});
$('#button_off159').click(function() {
	return false;
});
$('#button_off160').click(function() {
	return false;
});
$('#button_off161').click(function() {
	return false;
});
$('#button_off162').click(function() {
	return false;
});
$('#button_off163').click(function() {
	return false;
});
$('#button_off164').click(function() {
	return false;
});
$('#button_off165').click(function() {
	return false;
});
$('#button_off166').click(function() {
	return false;
});
$('#button_off167').click(function() {
	return false;
});
$('#button_off160').click(function() {
	return false;
});
$('#button_off169').click(function() {
	return false;
});
$('#button_off170').click(function() {
	return false;
});
$('#button_off171').click(function() {
	return false;
});
$('#button_off172').click(function() {
	return false;
});
$('#button_off173').click(function() {
	return false;
});
$('#button_off174').click(function() {
	return false;
});
$('#button_off175').click(function() {
	return false;
});
$('#button_off176').click(function() {
	return false;
});
$('#button_off177').click(function() {
	return false;
});
$('#button_off170').click(function() {
	return false;
});
$('#button_off179').click(function() {
	return false;
});
$('#button_off180').click(function() {
	return false;
});
$('#button_off181').click(function() {
	return false;
});
$('#button_off182').click(function() {
	return false;
});
$('#button_off183').click(function() {
	return false;
});
$('#button_off184').click(function() {
	return false;
});
$('#button_off185').click(function() {
	return false;
});
$('#button_off186').click(function() {
	return false;
});
$('#button_off187').click(function() {
	return false;
});
$('#button_off180').click(function() {
	return false;
});
$('#button_off189').click(function() {
	return false;
});
</script>
