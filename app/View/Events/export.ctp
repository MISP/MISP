<div class="event index">
    <h2><?php echo __('Export');?></h2>
    <p><?php echo __('Export functionality is designed to automatically generate signatures for intrusion detection systems. To enable signature generation for a given attribute, Signature field of this attribute must be set to Yes.
        Note that not all attribute types are applicable for signature generation, currently we only support NIDS signature generation for IP, domains, host names, user agents etc., and hash list generation for MD5/SHA1 values of file artifacts. Support for more attribute types is planned.');?>
    <br/>
    <p><?php echo __('Simply click on any of the following buttons to download the appropriate data.');?></p>
    <?php $i = 0;?>
    <script type="text/javascript">
        var jobsArray = new Array();
        var intervalArray = new Array();
        function queueInterval(i, k, id, progress, modified) {
            jobsArray[i] = id;
            intervalArray[i] = setInterval(function(){
                    if (id != -1 && progress < 100 && modified != "N/A") {
                        queryTask(k, i);
                    }
                }, 3000);
        }
        function editMessage(id, text) {
            document.getElementById("message" + id).innerHTML = text;
        }
    </script>
    <table class="table table-striped table-hover table-condensed">
        <?php
            $background = (!empty(Configure::read('MISP.background_jobs')) && empty(Configure::read('MISP.disable_cached_exports')));
            $fields = array(__('Type'), __('Last Update'), __('Description'), __('Outdated'), __('Filesize'), __('Progress'), __('Actions'));
            if (!$background) {
                unset($fields[1]);
                unset($fields[3]);
                unset($fields[4]);
                unset($fields[5]);
            }
            $headers = array();
            foreach ($fields as $field) {
                $headers[] = sprintf(
                    '<th style="text-align:center;">%s</th>',
                    $field
                );
            }
            echo sprintf(
                '<tr>%s</tr>',
                implode('', $headers)
            );
            foreach ($export_types as $k => $type) {
                $cells = array();
                $cells[] = sprintf(
                    '<td class="short">%s</td>',
                    h($type['type'])
                );
                if ($background) {
                    $cells[] = sprintf(
                        '<td id="update%s" class="short red">%s</td>',
                        h($i),
                        h($type['lastModified'])
                    );
                }
                $cells[] = sprintf(
                    '<td>%s%s</td>',
                    h($type['description']),
                    empty($type['params']['includeAttachments']) ? '' : sprintf(
                        ' <span class="%s">%s.</span>',
                        Configure::read('MISP.cached_attachments') ? 'green' : 'red',
                        Configure::read('MISP.cached_attachments') ? __('Attachments are enabled on this instance') : __('Attachments are disabled on this instance')
                    )
                );
                if ($background) {
                    $cells[] = sprintf(
                        '<td id="outdated%s">%s</td>',
                        h($i),
                        $type['recommendation'] ? '<span style="color:red;">' . __('Yes') . '</span>' : __('No')
                    );
                    $cells[] = sprintf(
                        '<td class="short" style="text-align:right;">%s</td>',
                        isset($type['filesize']) ? h($type['filesize']) : sprintf('<span class="red">%s</span>', __('N/A'))
                    );
                    $status = __('Loading…');
                    if ($type['progress'] == 0 && $type['lastModified'] != "N/A") {
                        $status = __('Queued');
                    } else if ($type['progress'] == 0 && $type['lastModified'] == "N/A") {
                        $status = '<span style="color:red;">' . __('N/A') . '</span>';
                    } else if ($type['progress'] == 100) {
                        if (isset($type['filesize'])) {
                            $status = __('Completed');
                        } else {
                            $status = '<span style="color:red;">' . __('N/A') . '</span>';
                        }
                    } else {
                        $status = h($type['progress']) . '%';
                    }
                    $cells[] = sprintf(
                        '<td style="width:150px;"><div id="barFrame%s" %s>%s</div><div id="message%s" style="text-align:center;display:block;">%s</div><script type="text/javascript">%s</script></td>',
                        h($i),
                        'class="progress progress-striped active" style="margin-bottom: 0px;display:none;"',
                        sprintf(
                            '<div id="bar%s" class="bar" style="width: %s%%;">%s</div>',
                            h($i),
                            h($type['progress']),
                            $status
                        ),
                        h($i),
                        $status,
                        sprintf(
                            '<script type="text/javascript">queueInterval("%s", "%s", "%s", "%s", "%s");</script>',
                            h($i),
                            h($k),
                            h($type['job_id']),
                            h($type['progress']),
                            h($type['lastModified'])
                        )
                    );
                }
                if ($background) {
                    $cells[] = sprintf(
                        '<td><span class="btn-group">%s%s</span></td>',
                        ($k === 'text') ? '' : $this->Html->link(__('Download'), array('action' => 'downloadExport', $k), array('class' => 'btn btn-inverse btn-small')),
                        sprintf(
                            '<button class="btn btn-inverse btn-small" id=button%s onClick="generate(\'%s\', \'%s\', \'%s\', \'%s\', \'%s\')" %s>%s</button>',
                            $i,
                            h($i),
                            h($k),
                            h($type['job_id']),
                            h($type['progress']),
                            h($type['lastModified']),
                            (!$type['recommendation']) ? 'disabled' : '',
                            __('Generate')
                        )
                    );
                } else {
                    $params = array();
                    foreach ($type['params'] as $param => $param_value) {
                        if ($param == 'includeAttachments') {
                            if ($param_value == 1 && Configure::read('MISP.cached_attachments')) {
                                $param_value = '1';
                            } else {
                                $param_value = '0';
                            }
                        }
                        $params[] = h($param) . ':' . strval(h($param_value));
                    }
                    $download_url = $baseurl . '/' . strtolower($type['scope']) . 's/restSearch/' . implode('/', $params) . '.json';
                    $cells[] = sprintf(
                        '<td><a href="%s" class="btn btn-inverse btn-small">%s</a></td>',
                        $download_url,
                        __('Download')
                    );
                }
                echo sprintf(
                    '<tr>%s</tr>',
                    implode('', $cells)
                );
                $i++;
            }
        ?>
    </table>
    <ul class="inline">
        <?php
            foreach ($sigTypes as $sigType) {
                echo sprintf(
                    '<li class="actions" style="text-align:center; width: auto; padding: 7px 2px;">%s</li>',
                    $background ?
                    $this->Html->link($sigType, array('action' => 'downloadExport', 'text', $sigType), array('class' => 'btn btn-inverse btn-small btn.active qet')) :
                    sprintf(
                        '<a href="%s" class="btn btn-inverse btn-small">%s</a>',
                        $baseurl . '/attributes/restSearch/returnFormat:text/type:' . $sigType . '.json',
                        h($sigType)
                    )
                );
            }
        ?>
    </ul>
</div>
<?php
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'export'));
?>
<script type="text/javascript">
    function generate(i, type, id, progress, modified) {
        $.ajax({
            url: "<?php echo $baseurl; ?>/jobs/cache/" + type,
            })
            .done(function(data) {
                jobsArray[i] = data;
                editMessage(i, "Adding...");
                queueInterval(i, type, data, 1, "Just now");
                disableButton(i);
            });
        }

    function queryTask(type, i){
        $.getJSON('<?php echo $baseurl; ?>/jobs/getProgress/cache_' + type, function(data) {
            var x = document.getElementById("bar" + i);
            x.style.width = data+"%";
            if (data > -1 && data < 100) {
                x.innerHTML = data + "%";
                showDiv("barFrame" + i);
                hideDiv("message" + i);
            }
            if (data == 100) {
                clearInterval(intervalArray[i]);
                hideDiv("barFrame" + i);
                showDiv("message" + i);
                updateTime(i);
                editMessage(i, "Completed.");
                updateOutdated(i);
            }
            if (data == -1) {
                alert("<?php echo __('Warning, the background worker is not responding!');?>");
            }
        });
    }

    function showDiv(id) {
        document.getElementById(id).style.display = 'block';
    }

    function hideDiv(id) {
        document.getElementById(id).style.display = 'none';
    }

    function updateTime(id) {
        document.getElementById("update" + id).innerHTML = "<?php echo __('0 seconds ago');?>";
    }

    function updateOutdated(id) {
        document.getElementById("outdated" + id).innerHTML = "<?php echo __('No');?>";
    }

    function disableButton(id) {
        $('#button' + id).prop('disabled', true);
    }
</script>
