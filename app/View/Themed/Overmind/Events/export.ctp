<?php
    // Title of the index displayed in the header section, leaving it empty will fallback to controller name
    $headerTitle = __('Exports');

    // Description displayed under the title in the header section, leave empty if not needed
    $headerDescription = __('');

    // Actions displayed as buttons in the header section, leave empty if not needed
    $headerActions = [];

    $this->set('headerTitle', $headerTitle);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);
?>

<div class="container-fluid">

    <div class="mb-4">
        <div class="alert alert-info shadow-sm" role="alert">
            <i class="fas fa-info-circle me-2"></i>
            <?php echo __('Export functionality is designed to automatically generate signatures for intrusion detection systems. To enable signature generation for a given attribute, Signature field of this attribute must be set to Yes.
            Note that not all attribute types are applicable for signature generation, currently we only support NIDS signature generation for IP, domains, host names, user agents etc., and hash list generation for MD5/SHA1 values of file artifacts. Support for more attribute types is planned.');?>
        </div>

        <?php if (Configure::read('MISP.disable_cached_exports', true)): ?>
            <div class="alert alert-danger shadow-sm border-start border-danger border-4 mt-3" role="alert">
                <strong><i class="fas fa-exclamation-triangle"></i> <?php echo __('Warning');?>:</strong> <?= __('This feature is disabled') ?>
            </div>
            <?php return ?>
        <?php endif; ?>

        <p class="lead text-dark mt-3"><?php echo __('Simply click on any of the following buttons to download the appropriate data.');?></p>
    </div>

    <?php $i = 0;?>

    <script type="text/javascript">
        var jobsArray = [];
        var intervalArray = [];

        function queueInterval(i, k, id, progress, modified) {
            jobsArray[i] = id;
            intervalArray[i] = setInterval(function(){
                if (id !== -1 && progress < 100 && modified !== "N/A") {
                    queryTask(k, i);
                }
            }, 3000);
        }

        function editMessage(id, text) {
            var msgEl = document.getElementById("message" + id);
            if (msgEl) {
                msgEl.innerHTML = text;
            }
        }
    </script>

    <div class="card shadow-sm mb-4">
        <div class="card-body p-0 table-responsive">
            <table class="table table-striped table-hover table-bordered table-sm align-middle mb-0">
                <thead class="table-dark">
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
                                '<th class="text-center py-2">%s</th>',
                                $field
                            );
                        }
                        echo sprintf(
                            '<tr>%s</tr>',
                            implode('', $headers)
                        );
                    ?>
                </thead>
                <tbody>
                    <?php
                        foreach ($export_types as $k => $type) {
                            $cells = array();
                            // Type column
                            $cells[] = sprintf(
                                '<td class="text-center fw-bold"><span class="badge bg-secondary">%s</span></td>',
                                h($type['type'])
                            );

                            // Last Update column (Background mode)
                            if ($background) {
                                $cells[] = sprintf(
                                    '<td id="update%s" class="text-danger fw-bold text-nowrap text-center">%s</td>',
                                    h($i),
                                    h($type['lastModified'])
                                );
                            }

                            // Description column
                            $cells[] = sprintf(
                                '<td>%s%s</td>',
                                h($type['description']),
                                empty($type['params']['includeAttachments']) ? '' : sprintf(
                                    ' <span class="fw-bold %s">%s.</span>',
                                    Configure::read('MISP.cached_attachments') ? 'text-success' : 'text-danger',
                                    Configure::read('MISP.cached_attachments') ? __('Attachments are enabled on this instance') : __('Attachments are disabled on this instance')
                                )
                            );

                            // Progress & Status columns (Background mode)
                            if ($background) {
                                $cells[] = sprintf(
                                    '<td id="outdated%s" class="text-center">%s</td>',
                                    h($i),
                                    $type['recommendation'] ? '<span class="text-danger fw-bold">' . __('Yes') . '</span>' : '<span class="text-success">' . __('No') . '</span>'
                                );
                                $cells[] = sprintf(
                                    '<td class="text-end text-nowrap">%s</td>',
                                    isset($type['filesize']) ? h($type['filesize']) : sprintf('<span class="text-danger fw-bold">%s</span>', __('N/A'))
                                );

                                $status = __('Loading…');
                                if ($type['progress'] == 0 && $type['lastModified'] != "N/A") {
                                    $status = __('Queued');
                                } else if ($type['progress'] == 0 && $type['lastModified'] == "N/A") {
                                    $status = '<span class="text-danger fw-bold">' . __('N/A') . '</span>';
                                } else if ($type['progress'] == 100) {
                                    if (isset($type['filesize'])) {
                                        $status = __('Completed');
                                    } else {
                                        $status = '<span class="text-danger fw-bold">' . __('N/A') . '</span>';
                                    }
                                } else {
                                    $status = h($type['progress']) . '%';
                                }

                                $cells[] = sprintf(
                                    '<td style="width:150px; vertical-align: middle;">
                                        <div id="barFrame%s" class="progress mb-1 shadow-sm" style="height: 1.25rem; display:none;">
                                            %s
                                        </div>
                                        <div id="message%s" class="text-center small fw-bold text-muted mt-1" style="display:block;">%s</div>
                                        <script type="text/javascript">%s</script>
                                    </td>',
                                    h($i),
                                    sprintf(
                                        '<div id="bar%s" class="progress-bar progress-bar-striped progress-bar-animated bg-info text-dark fw-bold" role="progressbar" style="width: %s%%;">%s</div>',
                                        h($i),
                                        h($type['progress']),
                                        $status
                                    ),
                                    h($i),
                                    $status,
                                    sprintf(
                                        'queueInterval("%s", "%s", "%s", "%s", "%s");',
                                        h($i),
                                        h($k),
                                        h($type['job_id']),
                                        h($type['progress']),
                                        h($type['lastModified'])
                                    )
                                );
                            }

                            // Actions column
                            if ($background) {
                                $cells[] = sprintf(
                                    '<td class="text-center"><div class="btn-group shadow-sm">%s%s</div></td>',
                                    ($k === 'text') ? '' : str_replace('btn-inverse btn-small', 'btn-dark btn-sm', $this->Html->link('<i class="fas fa-download"></i> ' . __('Download'), array('action' => 'downloadExport', $k), array('class' => 'btn btn-dark btn-sm', 'escape' => false))),
                                    sprintf(
                                        '<button class="btn btn-outline-dark btn-sm" id=button%s onClick="generate(\'%s\', \'%s\', \'%s\', \'%s\', \'%s\')" %s><i class="fas fa-sync-alt"></i> %s</button><div class="d-none">%s</div>',
                                        $i,
                                        h($i),
                                        h($k),
                                        h($type['job_id']),
                                        h($type['progress']),
                                        h($type['lastModified']),
                                        (!$type['recommendation']) ? 'disabled' : '',
                                        __('Generate'),
                                        $this->Form->postLink(__('Download'), array('controller' => 'jobs', 'action' => 'cache', h($k)), array('class' => 'btn btn-dark btn-sm')),
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
                                    '<td class="text-center"><a href="%s" class="btn btn-dark btn-sm shadow-sm"><i class="fas fa-download"></i> %s</a></td>',
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
                </tbody>
            </table>
        </div>
    </div>

    <div class="mt-4">
        <h5 class="fw-bold mb-3 text-primary"><?php echo __('Available Text Signature Types'); ?></h5>
        <div class="d-flex flex-wrap gap-2">
            <?php
                foreach ($sigTypes as $sigType) {
                    echo $background ?
                        str_replace('btn-inverse btn-small btn.active qet', 'btn-outline-dark btn-sm shadow-sm', $this->Html->link($sigType, array('action' => 'downloadExport', 'text', $sigType), array('class' => 'btn btn-outline-dark btn-sm shadow-sm'))) :
                        sprintf(
                            '<a href="%s" class="btn btn-outline-dark btn-sm shadow-sm">%s</a>',
                            $baseurl . '/attributes/restSearch/returnFormat:text/type:' . $sigType . '.json',
                            h($sigType)
                        );
                }
            ?>
        </div>
    </div>
</div>

<script type="text/javascript">
    function generate(i, type, id, progress, modified) {
        var clickedBtn = document.getElementById('button' + i);
        var formContainer = clickedBtn.nextElementSibling;
        var form = formContainer.querySelector('form');
        var originalHtml = clickedBtn.innerHTML;
        clickedBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';

        var actionUrl = form.getAttribute('action');
        var formData = new FormData(form);
        var urlEncodedData = new URLSearchParams(formData).toString();

        fetch(actionUrl, {
            method: 'POST',
            body: urlEncodedData,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
            }
        })
        .then(function(response) {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.text();
        })
        .then(function(data) {
            jobsArray[i] = data;
            editMessage(i, "Adding...");
            queueInterval(i, type, data, 1, "Just now");
            disableButton(i);
            clickedBtn.innerHTML = originalHtml;
        })
        .catch(function(error) {
            console.error('There has been a problem with your fetch operation:', error);
            clickedBtn.innerHTML = originalHtml;
        });
    }

    function queryTask(type, i) {
        fetch('<?php echo $baseurl; ?>/jobs/getProgress/cache_' + type, {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            }
        })
        .then(function(response) {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(function(data) {
            var x = document.getElementById("bar" + i);
            if (!x) return;

            x.style.width = data + "%";

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
                editMessage(i, "<span class='text-success'><i class='fas fa-check-circle'></i> Completed.</span>");
                updateOutdated(i);
            }
            if (data == -1) {
                alert("<?php echo __('Warning, the background worker is not responding!');?>");
            }
        })
        .catch(function(error) {
            console.error('Fetch error:', error);
        });
    }

    function showDiv(id) {
        var el = document.getElementById(id);
        if (el) el.style.display = 'block';
    }

    function hideDiv(id) {
        var el = document.getElementById(id);
        if (el) el.style.display = 'none';
    }

    function updateTime(id) {
        var el = document.getElementById("update" + id);
        if (el) el.innerHTML = "<?php echo __('0 seconds ago');?>";
    }

    function updateOutdated(id) {
        var el = document.getElementById("outdated" + id);
        if (el) el.innerHTML = "<span class='text-success'><?php echo __('No');?></span>";
    }

    function disableButton(id) {
        var btn = document.getElementById('button' + id);
        if (btn) btn.disabled = true;
    }
</script>