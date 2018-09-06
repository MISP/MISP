<div class="event index">
    <h2><?php echo __('Export');?></h2>
    <p><?php echo __('Export functionality is designed to automatically generate signatures for intrusion detection systems. To enable signature generation for a given attribute, Signature field of this attribute must be set to Yes.
        Note that not all attribute types are applicable for signature generation, currently we only support NIDS signature generation for IP, domains, host names, user agents etc., and hash list generation for MD5/SHA1 values of file artifacts. Support for more attribute types is planned.');?>
    <br/>
    <p><?php echo __('Simply click on any of the following buttons to download the appropriate data.');?></p>

    <div class="row bottom-buffer">
        <div class="span3">
        <?php echo $this->Html->link(__('Download all as XML'), array('action' => 'xml', 'download'), array('class' => 'btn btn-block full-width')); ?>
        </div>
        <div class="span9"><?php echo __('Click this to download all events and attributes that you have access to <small>(except file attachments)</small> in a custom XML format.');?>
        </div>
    </div>
    <div class="row bottom-buffer">
        <div class="span3">
        <?php echo $this->Html->link(__('Download all signatures as CSV'), array('action' => 'csv', 'download'), array('class' => 'btn btn-block full-width')); ?>
        </div>
        <div class="span9"><?php echo __('Click this to download all attributes that are indicators and that you have access to <small>(except file attachments)</small> in CSV format.');?>
        </div>
    </div>
        <div class="row bottom-buffer">
        <div class="span3">
        <?php echo $this->Html->link(__('Download all as CSV'), array('action' => 'csv', 'download', '0','1'), array('class' => 'btn btn-block full-width')); ?>
        </div>
        <div class="span9"><?php echo __('Click this to download all attributes that you have access to <small>(except file attachments)</small> in CSV format.');?>
        </div>
    </div>
    <div class="row bottom-buffer">
        <div class="span3">
        <?php echo $this->Html->link(__('Download Suricata signatures'), array('action' => 'nids', 'suricata', 'download'), array('class' => 'btn btn-block full-width')); ?>
        <?php echo $this->Html->link(__('Download Snort signatures'), array('action' => 'nids', 'snort', 'download'), array('class' => 'btn btn-block full-width')); ?>
        </div>
        <div class="span9"><?php echo __('Click these to download all network related attributes that you
                        have access to under the Suricata or Snort rule format. Only <em>published</em>
                        events and attributes marked as <em>IDS Signature</em> are exported.
                        Administration is able to maintain a whitelist containing host,
                        domain name and IP numbers to exclude from the NIDS export.');?>
        </div>
    </div>
    <div class="row bottom-buffer">
        <div class="span3">
        <?php echo $this->Html->link(__('Download Bro signatures'), array('controller' => 'attributes', 'action' => 'bro', 'download'), array('class' => 'btn btn-block full-width')); ?>
        </div>
        <div class="span9"><?php echo __('Click these to download all network related attributes that you
                have access to under the Bro rule format. Only <em>published</em>
                events and attributes marked as <em>IDS Signature</em> are exported.
                Administration is able to maintain a whitelist containing host,
                domain name and IP numbers to exclude from the NIDS export.');?>
        </div>
     </div>
    <div class="row bottom-buffer">
        <div class="span3">
        <?php echo $this->Html->link(__('Download RPZ Zone File'), array('controller' => 'attributes', 'action' => 'rpz', 'download'), array('class' => 'btn btn-block full-width')); ?>
        </div>
        <div class="span9"><?php echo __('Click this to download an RPZ Zone file generated from all ip-src/ip-dst, hostname, domain attributes. This can be useful for DNS level firewalling. Only published events and attributes marked as IDS Signature are exported.');?>
        </div>
    </div>
    <div class="row bottom-buffer">
        <div class="span3">
            <?php echo $this->Html->link(__('Download all MD5 hashes'), array('action' => 'hids', 'md5','download'), array('class' => 'btn btn-block full-width')); ?>
            <?php echo $this->Html->link(__('Download all SHA1 hashes'), array('action' => 'hids', 'sha1','download'), array('class' => 'btn btn-block full-width')); ?>
        </div>
        <div class="span9"><?php echo __('Click on one of these two buttons to download all MD5 or SHA1
                        checksums contained in file-related attributes. This list can be
                        used to feed forensic software when searching for susipicious files.
                        Only <em>published</em> events and attributes marked as <em>IDS
                            Signature</em> are exported.');?>
        </div>
    </div>
    <p>
    <?php echo __('Click on one of these buttons to download all the attributes with the matching type. This list can be used to feed forensic software when searching for susipicious files. Only <em>published</em> events and attributes marked as <em>IDS Signature</em> are exported.');?>
    </p>

    <ul class="inline">
    <?php
    foreach ($sigTypes as $sigType): ?>
        <li class="actions" style="text-align:center; width: auto; padding: 7px 2px;">
        <?php echo $this->Html->link($sigType, array('controller' => 'attributes', 'action' => 'text', 'download' ,$sigType), array('class' => 'btn')) ?>
        </li>
    <?php endforeach; ?>
    </ul>

</div>
<div class="actions <?php echo $debugMode;?>">
    <ul class="nav nav-list">
        <li><a href="<?php echo $baseurl;?>/events/index"><?php echo __('List Events');?></a></li>
        <?php if ($isAclAdd): ?>
        <li><a href="<?php echo $baseurl;?>/events/add"><?php echo __('Add Event');?></a></li>
        <?php endif; ?>
        <li class="divider"></li>
        <li><a href="<?php echo $baseurl;?>/attributes/index"><?php echo __('List Attributes');?></a></li>
        <li><a href="<?php echo $baseurl;?>/attributes/search"><?php echo __('Search Attributes');?></a></li>
        <li class="divider"></li>
        <li class="active"><a href="<?php echo $baseurl;?>/events/export"><?php echo __('Export');?></a></li>
        <?php if ($isAclAuth): ?>
        <li><a href="<?php echo $baseurl;?>/events/automation"><?php echo __('Automation');?></a></li>
        <?php endif;?>
    </ul>
</div>
