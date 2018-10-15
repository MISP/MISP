<div class="actions <?php echo $debugMode;?>">
    <ol class="nav nav-list">
            <li class="active"><?php echo $this->Html->link(__('Categories and Types'), array('controller' => 'pages', 'action' => 'display', 'doc', 'categories_and_types')); ?></li>
    </ol>
</div>
<div class="index">
<h2><?php echo __('Attribute Categories and Types');?></h2>
<h3><?php echo __('Attribute Categories vs. Types');?></h3>
<table class="table table-striped table-hover table-condensed table-bordered">
    <tr>
        <th><?php echo __('Category');?></th>
        <?php foreach ($categoryDefinitions as $cat => $catDef):    ?>
        <th style="width:5%; text-align:center; white-space:normal">
            <a href="#<?php echo $cat; ?>"><?php echo $cat; ?></a>
        </th>
        <?php endforeach; ?>
        <th><?php echo __('Category');?></th>
    </tr>
    <?php foreach ($typeDefinitions as $type => $def): ?>
    <tr>
        <th><a href="#<?php echo $type; ?>"><?php echo $type; ?></a></th>
        <?php foreach ($categoryDefinitions as $cat => $catDef): ?>
        <td style="text-align:center">
            <?php echo in_array($type, $catDef['types'])? 'X' : ''; ?>
        </td>
        <?php endforeach; ?>
        <th><a href="#<?php echo $type; ?>"><?php echo $type; ?></a></th>
    <?php endforeach; ?>
    </tr>
<tr>
    <th><?php echo __('Category');?></th>
    <?php foreach ($categoryDefinitions as $cat => $catDef): ?>
    <th style="width:5%; text-align:center; white-space:normal">
        <a href="#<?php echo $cat; ?>"><?php echo $cat; ?></a>
    </th>
    <?php endforeach; ?>
    <th><?php echo __('Category');?></th>
</tr>
</table>
<h3><?php echo __('Categories');?></h3>
<table class="table table-striped table-condensed table-bordered">
    <tr>
        <th><?php echo __('Category');?></th>
        <th><?php echo __('Description');?></th>
    </tr>
    <?php foreach ($categoryDefinitions as $cat => $def): ?>
    <tr>
        <th><a id="<?php echo $cat; ?>"></a>
            <?php echo $cat; ?>
        </th>
        <td>
            <?php echo isset($def['formdesc'])? $def['formdesc'] : $def['desc']; ?>
        </td>
    </tr>
    <?php endforeach; ?>
</table>
<h3><?php echo __('Types');?></h3>
<table class="table table-striped table-condensed table-bordered">
    <tr>
        <th><?php echo __('Type');?></th>
        <th><?php echo __('Description');?></th>
    </tr>
    <?php foreach ($typeDefinitions as $type => $def): ?>
    <tr>
        <th><a id="<?php echo $type; ?>"></a>
            <?php echo $type; ?>
        </th>
        <td>
            <?php echo isset($def['formdesc'])? $def['formdesc'] : $def['desc']; ?>
        </td>
    </tr>
    <?php endforeach;?>
</table>
<p><a href="<?php echo $baseurl;?>/pages/display/doc/md/categories_and_types"><?php echo __('Click here to get the .md version for gitbook generation.');?></a></p>
</div>
