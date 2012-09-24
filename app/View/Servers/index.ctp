<?php
$mayAdd = $isAclAdd;
$buttonAddStatus = $mayAdd ? 'button_on':'button_off';
$mayModify = $isAclModify;
$buttonModifyStatus = $mayModify ? 'button_on':'button_off';
$buttonCounter = 0;
?>
<div class="servers index">
	<h2><?php echo __('Servers');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('push');?></th>
			<th><?php echo $this->Paginator->sort('pull');?></th>
			<th><?php echo $this->Paginator->sort('url');?></th>
			<th>From</th>
			<?php if ($isAdmin): ?>
			<th><?php echo $this->Paginator->sort('org');?></th>
			<?php endif; ?>
			<th>Last Pulled ID</th>
			<th>Last Pushed ID</th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
	foreach ($servers as $server): ?>
	<tr>
		<td class="short" style="text-align: center;"><?php echo ($server['Server']['push'])? 'Yes' : 'No'; ?>&nbsp;</td>
		<td class="short" style="text-align: center;"><?php echo ($server['Server']['pull'])? 'Yes' : 'No'; ?>&nbsp;</td>
		<td><?php echo h($server['Server']['url']); ?>&nbsp;</td>
		<td><?php echo h($server['Server']['organization']); ?>&nbsp;</td>
		<?php if ($isAdmin): ?>
		<td class="short"><?php echo h($server['Server']['org']); ?>&nbsp;</td>
		<?php endif; ?>
		<td class="short"><?php echo $server['Server']['lastpulledid']; ?></td>
		<td class="short"><?php echo $server['Server']['lastpushedid']; ?></td>
		<td class="actions">
			<?php echo $this->Html->link(__('Edit'), array('action' => 'edit', $server['Server']['id']), $isAclModify || ($server['Server']['org'] == $me['org']) ? null : array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus)); ?>
			<?php if ($mayModify || $server['Server']['org'] == $me['org']) echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $server['Server']['id']), null, __('Are you sure you want to delete # %s?', $server['Server']['id']));
			else echo $this->Html->link(__('Delete'), array('action' => 'delete', $server['Server']['id']), array('id' => $buttonModifyStatus . $buttonCounter++, 'class' => $buttonModifyStatus)); ?>

			<?php // if ($server['Server']['pull']) echo $this->Form->postLink(__('Pull'), array('action' => 'pull', $server['Server']['id']) ); ?>
			<?php // if ($server['Server']['push']) echo $this->Form->postLink(__('Push'), array('action' => 'push', $server['Server']['id']) ); ?>

			<?php if ($server['Server']['pull']) echo $this->Form->postLink(__('Pull All'), array('action' => 'pull', $server['Server']['id'], 'full') ); ?>
			<?php if ($server['Server']['push']) echo $this->Form->postLink(__('Push All'), array('action' => 'push', $server['Server']['id'], 'full') ); ?>
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
	<?php
		echo $this->Paginator->prev('< ' . __('previous'), array(), null, array('class' => 'prev disabled'));
		echo $this->Paginator->numbers(array('separator' => ''));
		echo $this->Paginator->next(__('next') . ' >', array(), null, array('class' => 'next disabled'));
	?>
	</div>

</div>
<div class="actions">
	<ul>
		<li><?php echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add'), array('id' => $buttonAddStatus . $buttonCounter++, 'class' => $buttonAddStatus)); ?></li>
		<li><?php echo $this->Html->link(__('List Servers'), array('controller' => 'servers', 'action' => 'index'));?></li>
		<li>&nbsp;</li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
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
});
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
</script>
