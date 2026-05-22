<?php
    // Title of the index displayed in the header section, leaving it empty will fallback to controller name
    $headerTitle = __('Automation API');

    // Description displayed under the title in the header section, leave empty if not needed
    $headerDescription = __('');

    // Actions displayed as buttons in the header section, leave empty if not needed
    $headerActions = [];

    $this->set('headerTitle', $headerTitle);
    $this->set('headerDescription', $headerDescription);
    $this->set('headerActions', $headerActions);

    $api_key = empty(Configure::read('Security.advanced_authkeys')) ? $authkey : 'YOUR_API_KEY';
?>
<div class="container-fluid">
    
    <div class="mb-4">
        <p class="lead fw-bold">
            <?php echo __('Check out the <a href="%s" class="text-decoration-none">OpenAPI spec of the MISP Automation API</a>.', $baseurl . '/api/openapi');?>
        </p>
        <p class="text-muted">
            <?php echo __('Automation functionality is designed to automatically feed other tools and systems with the data in your MISP repository. To make this functionality available for automated tools an authentication key is used.');?>
            <br />
            <?php echo __('You can use the <a href="' . $baseurl . '/api/rest" class="text-decoration-none">REST client</a> to test your API queries against your MISP and export the resulting tuned queries as curl or python scripts.');?>
            <br />
            <?php echo __('You can view the <a href="' . $baseurl . '/automation/1" class="text-decoration-none">old MISP automation page</a>.');?>
        </p>
    </div>

    <div class="row mb-4">
        <div class="col-md-12">
            <div class="alert alert-danger shadow-sm border-start border-danger border-4" role="alert">
                <h5 class="alert-heading"><i class="fas fa-exclamation-triangle"></i> <?php echo __('Warning'); ?></h5>
                <p class="mb-0"><?php echo __('Make sure you keep your API key secret as it gives access to all of the data that you normally have access to in MISP.');?></p>
            </div>

            <div class="alert alert-info shadow-sm" role="alert">
                <i class="fas fa-key"></i> 
                <?php
                    if (empty(Configure::read('Security.advanced_authkeys'))) {
                        echo __(
                            'Your current key is: <code class="fs-6 bg-light p-1 rounded text-dark border">%s</code>. You can %s this key.',
                            $api_key,
                            $this->Form->postLink(
                                __('reset'),
                                array('controller' => 'users', 'action' => 'resetauthkey', 'me'),
                                array('class' => 'btn btn-sm btn-outline-danger ms-2', 'div' => false)
                            )
                        );
                    } else {
                        echo __(
                            'You can view and manage your API keys under your profile, found %s',
                            sprintf(
                                '<a href="%s/users/view/me" class="alert-link">%s</a>',
                                $baseurl,
                                __('here')
                            )
                        );
                    }
                ?>
            </div>
        </div>
    </div>


    <ul class="nav nav-tabs mb-3" id="automationTabs" role="tablist">
        <li class="nav-item">
            <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#searchFilter">
                🔍 Search & Filtering
            </button>
        </li>
        <li class="nav-item">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#exports">
                📤 Export & Data Extraction
            </button>
        </li>
        <li class="nav-item">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#samples">
                📥 Samples & Attachments
            </button>
        </li>
        <li class="nav-item">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#tags">
                🏷️ Events, Tags & Proposals
            </button>
        </li>
        <li class="nav-item">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#automation">
                ⚙️ Automation & Processing
            </button>
        </li>
        <li class="nav-item">
            <button class="nav-link" data-bs-toggle="tab" data-bs-target="#cli">
                🧑‍💻 Administration & CLI
            </button>
        </li>
    </ul>

    <div class="tab-content">

        <!-- SEARCH TAB -->
        <div class="tab-pane fade show active" id="searchFilter">
            <div class="accordion" id="searchAccordion">

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button" data-bs-toggle="collapse" data-bs-target="#search">
                            Search
                        </button>
                    </h2>
                    <div id="search" class="accordion-collapse collapse show">
                        <div class="accordion-body">
                            <?php
                                $data = array(
                                    'title' => __('Search'),
                                    'description' => array(
                                        __('It is possible to search the database for attributes based on a list of criteria.'),
                                        __('To return an event or a list of events in a desired format, use the following syntax.'),
                                        __('Whilst a list of parameters is provided below, it isn\'t necessarily exhaustive, specific export formats could have additional parameters.')
                                    ),
                                    'parameters' => array(
                                        "returnFormat" => __('Set the return format of the search (Currently supported: json, xml, openioc, suricata, snort - more formats are being moved to restSearch with the goal being that all searches happen through this API). Can be passed as the first parameter after restSearch or via the JSON payload.'),
                                        "limit" => __('Limit the number of results returned, depending on the scope (for example 10 attributes or 10 full events).'),
                                        "page" => __('If a limit is set, sets the page to be returned. page 3, limit 100 will return records 201->300).'),
                                        "value" => __('Search for the given value in the attributes\' value field.'),
                                        "type" => __('The attribute type, any valid MISP attribute type is accepted.'),
                                        "category" => __('The attribute category, any valid MISP attribute category is accepted.'),
                                        "org" => __('Search by the creator organisation by supplying the organisation identifier.'),
                                        "tags" => __('To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a \'!\'.'),
                                        "quickfilter" => __('Enabling this (by passing "1" as the argument) will make the search ignore all of the other arguments, except for the auth key and value. MISP will return an xml / json (depending on the header sent) of all events that have a sub-string match on value in the event info, event orgc, or any of the attribute value1 / value2 fields, or in the attribute comment.'),
                                        "from" => __('Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.'),
                                        "to" => __('Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.'),
                                        "eventid" => __('The events that should be included / excluded from the search'),
                                        "withAttachments" => __('If set, encodes the attachments / zipped malware samples as base64 in the data field within each attribute'),
                                        "metadata" => __('Only the metadata (event, tags, relations) is returned, attributes and proposals are omitted.'),
                                        "uuid" => __('Restrict the results by uuid.'),
                                        "publish_timestamp" => __('Restrict the results by the timestamp of the last publishing of the event. The input can be a timestamp or a short-hand time description (7d or 24h for example). You can also pass a list with two values to set a time range (for example ["14d", "7d"]).'),
                                        "last" => __('(Deprecated synonym for publish_timestamp) Restrict the results by the timestamp of the last publishing of the event. The input can be a timestamp or a short-hand time description (7d or 24h for example). You can also pass a list with two values to set a time range (for example ["14d", "7d"]).'),
                                        "timestamp" => __('Restrict the results by the timestamp (last edit). Any event with a timestamp newer than the given timestamp will be returned. In case you are dealing with /attributes as scope, the attribute\'s timestamp will be used for the lookup. The input can be a timestamp or a short-hand time description (7d or 24h for example). You can also pass a list with two values to set a time range (for example ["14d", "7d"]).'),
                                        "published" => __('Set whether published or unpublished events should be returned. Do not set the parameter if you want both.'),
                                        "extending" => __("Set whether events that extend another or events that don't should be returned. Do not set the parameter if you want both."),
                                        "extended" => __('Set whether events that are extended or not should be returned. Do not set the parameter if you want both.'),
                                        "enforceWarninglist" => __('Remove any attributes from the result that would cause a hit on a warninglist entry.'),
                                        "to_ids" => __('By default (0) all attributes are returned that match the other filter parameters, regardless of their to_ids setting. To restrict the returned data set to to_ids only attributes set this parameter to 1. You can only use the special "exclude" setting to only return attributes that have the to_ids flag disabled.'),
                                        "deleted" => __('Default value 0. If set to 1, only soft-deleted attributes will be returned. If set to [0,1] , both deleted and non-deleted attributes will be returned.'),
                                        "includeEventUuid" => __('Instead of just including the event ID, also include the event UUID in each of the attributes.'),
                                        "event_timestamp" => __('Only return attributes from events that have received a modification after the given timestamp. The input can be a timestamp or a short-hand time description (7d or 24h for example). You can also pass a list with two values to set a time range (for example ["14d", "7d"]).'),
                                        "sgReferenceOnly" => __('If this flag is set, sharing group objects will not be included, instead only the sharing group ID is set.'),
                                        "eventinfo" => __("Filter on the event's info field."),
                                        "searchall" => __("Search for a full or a substring (delimited by % for substrings) in the event info, event tags, attribute tags, attribute values or attribute comment fields."),
                                        "attackGalaxy" => __("Select the ATT&CK matrix like galaxy to use when using returnFormat = attack. Defaults to the Mitre ATT&CK library via mitre-attack-pattern.")
                                    ),
                                    'url' => array(
                                        $baseurl . '/attributes/restSearch',
                                        $baseurl . '/events/restSearch'
                                    )
                                );
                            ?>
                            <p class="card-text"><?php echo implode(" ", $data['description']); ?></p>
                            <div class="bg-light p-3 rounded border mb-4">
                                <pre class="mb-0"><code><?php echo implode("\n", $data['url']); ?></code></pre>
                            </div>
                            <h6 class="fw-bold mb-3"><?php echo __('The list of valid parameters'); ?></h6>
                            <div class="table-responsive">
                                <table class="table table-bordered table-striped table-sm">
                                    <thead class="table-light">
                                        <tr>
                                            <th style="width: 20%;"><?php echo __('Parameter'); ?></th>
                                            <th><?php echo __('Description'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($data['parameters'] as $k => $v): ?>
                                            <tr>
                                                <td class="fw-bold text-nowrap"><span class="badge bg-secondary"><?php echo $k; ?></span></td>
                                                <td><?php echo $v; ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>

                            <?php
                                $description = __('To export all attributes of types ip-src and ip-dst that have a TLP marking and are not marked TLP:red, use the syntax below. String searches are by default exact lookups, but you can use mysql style "%" wildcards to do substring searches.');
                                $url = $baseurl . '/attributes/restSearch';
                                $headers = array(
                                    'Accept: application/json',
                                    'Content-type: application/json',
                                    'Authorization: ' . $api_key
                                );
                                $headers = implode("\n", $headers);
                                $body = json_encode(
                                    array(
                                        'returnFormat' => 'json',
                                        'type' => array('OR' => array('ip-src', 'ip-dst')),
                                        'tags' => array('NOT' => array('tlp:red'), 'OR' => array('tlp:%')),
                                    ), JSON_PRETTY_PRINT);
                            ?>
                            <hr class="my-4">
                            <h5 class="fw-bold mb-3"><?php echo __('Example Request'); ?></h5>
                            <p><?php echo $description; ?></p>
                            <div class="row g-3">
                                <div class="col-md-12">
                                    <span class="badge bg-primary">URL</span>
                                    <pre class="bg-light p-2 rounded border mt-1 mb-0"><code><?php echo $url; ?></code></pre>
                                </div>
                                <div class="col-md-6">
                                    <span class="badge bg-info text-dark">Headers</span>
                                    <pre class="bg-light p-2 rounded border mt-1 mb-0"><code><?php echo $headers; ?></code></pre>
                                </div>
                                <div class="col-md-6">
                                    <span class="badge bg-warning text-dark">Body</span>
                                    <pre class="bg-light p-2 rounded border mt-1 mb-0"><code><?php echo $body; ?></code></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#galaxyCluster">
                            Galaxy Cluster Search
                        </button>
                    </h2>
                    <div id="galaxyCluster" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <?php
                                $data = array(
                                    'title' => __('Galaxy Cluster Search'),
                                    'description' => array(
                                        __('It is possible to search the database for galaxy clusters based on a list of criteria.'),
                                        __('To return a cluster or a list of clusters in the JSON format, use the following syntax.'),
                                        __('Whilst a list of parameters is provided below, it isn\'t necessarily exhaustive')
                                    ),
                                    'parameters' => array(
                                        'limit' => __('Limit the number of results returned, depending on the scope (for example 10 clusters).'),
                                        'page' => __('If a limit is set, sets the page to be returned. page 3, limit 100 will return records 201->300).'),
                                        'id' => __('Specify the exact local ID the be returned'),
                                        'uuid' => __('Specify the exact local UUID the be returned'),
                                        'galaxy_id' => __('Specify the exact local ID of the galaxy containing all the clusters to be returned'),
                                        'galaxy_uuid' => __('Specify the exact local UUID of the galaxy containing all the clusters to be returned'),
                                        'published' => __('Specify the publication state of the clusters to be returned'),
                                        'value' => __('Specify the value of the clusters to be returned'),
                                        'extends_uuid' => __('Specify the UUID of the cluster that was forked by the returned clusters'),
                                        'extends_version' => __('Specify the version of the cluster that was forked by the returned clusters'),
                                        'version' => __('Specify the version to be returned'),
                                        'distribution' => __('Specify the distribution to be returned'),
                                        'org_id' => __('Specify the org_id to get all clusters belonging to this organisation.'),
                                        'orgc_id' => __('Specify the orgc_id to get all clusters that were created by this organisation.'),
                                        'tag_name' => __('Specify the tag name of the cluster to be returned'),
                                        'custom' => __('Specify if custom, default or both clusters should be returned'),
                                        'minimal' => __('Only return the UUID and the version of the returned clusters'),
                                    ),
                                    'url' => array(
                                        $baseurl . '/galaxy_clusters/restSearch',
                                    )
                                );
                            ?>
                            <p class="card-text"><?php echo implode(" ", $data['description']); ?></p>
                            <div class="bg-light p-3 rounded border mb-4">
                                <pre class="mb-0"><code><?php echo implode("\n", $data['url']); ?></code></pre>
                            </div>
                            <h6 class="fw-bold mb-3"><?php echo __('The list of valid parameters:'); ?></h6>
                            <div class="table-responsive">
                                <table class="table table-bordered table-striped table-sm">
                                    <thead class="table-light">
                                        <tr>
                                            <th style="width: 20%;"><?php echo __('Parameter'); ?></th>
                                            <th><?php echo __('Description'); ?></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($data['parameters'] as $k => $v): ?>
                                            <tr>
                                                <td class="fw-bold text-nowrap"><span class="badge bg-secondary"><?php echo $k; ?></span></td>
                                                <td><?php echo $v; ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#metadata">
                            Filtering event metadata
                        </button>
                    </h2>
                    <div id="metadata" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <p><?php echo __('As described in the REST section, it is possible to retrieve a list of events along with their metadata by sending a GET request to the /events API. However, this API in particular is a bit more versatile. You can pass search parameters along to search among the events on various fields and retrieve a list of matching events (along with their metadata). Use the following URL');?>:</p>

                            <div class="bg-light p-2 rounded border mb-4">
                                <pre class="mb-0"><code><?php echo $baseurl.'/events/index'; ?></code></pre>
                            </div>

                            <p><?php echo __('POST a JSON object with the desired lookup fields and values to receive a JSON back.');?><br />
                            <strong><?php echo __('An example for a valid lookup');?>:</strong></p>

                            <div class="row g-3 mb-4">
                                <div class="col-md-12">
                                    <span class="badge bg-primary">URL</span>
                                    <pre class="bg-light p-2 rounded border mt-1 mb-0"><code><?php echo $baseurl.'/events/index'; ?></code></pre>
                                </div>
                                <div class="col-md-6">
                                    <span class="badge bg-info text-dark">Headers</span>
                                    <pre class="bg-light p-2 rounded border mt-1 mb-0 small"><code><?php
                                        echo 'Authorization: ' . $api_key . PHP_EOL;
                                        echo 'Accept: application/json' . PHP_EOL;
                                        echo 'Content-type: application/json';
                                    ?></code></pre>
                                </div>
                                <div class="col-md-6">
                                    <span class="badge bg-warning text-dark">Body</span>
                                    <pre class="bg-dark text-warning p-2 rounded border mt-1 mb-0 small"><code>{"searcheventinfo":"Locky", "searchpublished":1, "searchdistribution":!0}</code></pre>
                                </div>
                            </div>

                            <p class="text-muted small mb-4">
                                <?php echo __('The above would return any event that is published, not restricted to your organisation only that has the term "Locky" in its event description. You can use exclamation marks to negate a value wherever appropriate.');?>
                            </p>

                            <h6 class="fw-bold mb-3"><?php echo __('The list of valid parameters');?>:</h6>
                            <div class="table-responsive">
                                <table class="table table-bordered table-striped table-sm mb-0">
                                    <tbody>
                                        <tr><td style="width: 20%;" class="fw-bold"><span class="badge bg-secondary">searchpublished</span></td><td><?php echo __('Filters on published or unpublished events [0,1] - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searcheventinfo</span></td><td><?php echo __('Filters on strings found in the event info - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchtag</span></td><td><?php echo __('Filters on attached tag names - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searcheventid</span></td><td><?php echo __('Filters on specific event IDs - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchthreatlevel</span></td><td><?php echo __('Filters on a given event threat level [1,2,3,4] - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchdistribution</span></td><td><?php echo __('Filters on the distribution level [0,1,2,3] - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchextending</span></td><td><?php echo __("Filters on extending events or ones that don't [0,1] ");?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchextended</span></td><td><?php echo __('Filters on events that are extended or not [0,1] ');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchanalysis</span></td><td><?php echo __('Filters on the given analysis phase of the event [0,1,2] - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchattribute</span></td><td><?php echo __('Filters on a contained attribute value - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchvalue</span></td><td><?php echo __('Filter exact matches on the attribute value');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchorg</span></td><td><?php echo __('Filters on the creator organisation - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchemail</span></td><td><?php echo __('Filters on the creator user\'s email address (admin only) - negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchDatefrom</span></td><td><?php echo __('Filters on the date, anything newer than the given date in YYYY-MM-DD format is taken - non-negatable');?></td></tr>
                                        <tr><td class="fw-bold"><span class="badge bg-secondary">searchDateuntil</span></td><td><?php echo __('Filters on the date, anything older than the given date in YYYY-MM-DD format is taken - non-negatable');?></td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- EXPORT TAB -->
        <div class="tab-pane fade" id="exports">
            <div class="accordion" id="exportAccordion">

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button" data-bs-toggle="collapse" data-bs-target="#csv">
                            CSV specific parameters for the restSearch APIs
                        </button>
                    </h2>
                    <div id="csv" class="accordion-collapse collapse show">
                        <div class="accordion-body">
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item">
                                    <span class="fw-bold text-primary">requested_attributes</span>: 
                                    <?php echo __("CSV only, select the fields that you wish to include in the CSV export. By setting event level fields additionally, includeContext is not required to get event metadata.");?>
                                </li>
                                <li class="list-group-item">
                                    <span class="fw-bold text-primary">includeContext</span>: 
                                    <?php echo __("CSV only, add additional event level data to the export. The additional fields can be added via requested_attributes too with more granularity.");?>
                                </li>
                                <li class="list-group-item">
                                    <span class="fw-bold text-primary">headerless</span>: 
                                    <?php echo __('The CSV created when this setting is set to true will not contain the header row.'); ?>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#rpz">
                            RPZ specific parameters for the restSearch APIs
                        </button>
                    </h2>
                    <div id="rpz" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <p><?php echo __('You can export RPZ zone files for DNS level firewalling by using the RPZ export functionality of MISP. The file generated will include all of the IDS flagged domain, hostname and IP-src/IP-dst attribute values that you have access to.');?></p>
                            <p><?php echo __('MISP will inject header values into the zone file as well as define the action taken for each of the values that can all be overridden. By default these values are either the default values shipped with the application, or ones that are overridden by your site administrator. The values are as follows');?>:</p>
                            <div class="row mb-4">
                                <div class="col-md-6">
                                    <ul class="list-group">
                                        <?php foreach ($rpzSettings as $k => $v): ?>
                                        <li class="list-group-item d-flex justify-content-between align-items-center">
                                            <span class="fw-bold"><?php echo h($k);?></span>
                                            <span class="badge bg-secondary rounded-pill"><?php echo h($v);?></span>
                                        </li>
                                        <?php endforeach; ?>
                                    </ul>
                                </div>
                            </div>

                            <p class="fw-bold mt-3"><?php echo __('To override the above values, either use the url parameters as described below');?>:</p>
                            <div class="bg-light p-3 rounded border mb-4">
                                <pre class="mb-0"><code><?php echo $baseurl;?>/attributes/rpz/download/[tags]/[eventId]/[from]/[to]/[policy]/[walled_garden]/[ns]/[email]/[serial]/[refresh]/[retry]/[expiry]/[minimum_ttl]/[ttl]</code></pre>
                            </div>

                            <p class="fw-bold"><?php echo __('or POST an XML or JSON object with the above listed options');?>: </p>
                            <div class="row g-3">
                                <div class="col-md-6">
                                    <span class="badge bg-info text-dark">XML</span>
                                    <pre class="bg-light p-2 rounded border mt-1 mb-0"><code><?php echo h('<request><tags>OSINT&&!OUTDATED</tags><policy>Local-Data</policy><walled_garden>my.stop.page.net</walled_garden><refresh>5h</refresh></request>');?></code></pre>
                                </div>
                                <div class="col-md-6">
                                    <span class="badge bg-warning text-dark">JSON</span>
                                    <pre class="bg-light p-2 rounded border mt-1 mb-0"><code>{"request": {"tags": ["OSINT", "!OUTDATED"], "policy": "Local-Data", "walled_garden": "my.stop.page.net", "refresh": "5h"}</code></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#bro">
                            Bro IDS export
                        </button>
                    </h2>
                    <div id="bro" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <p><?php echo __('An export of all attributes of a specific bro type to a formatted plain text file. By default only published and IDS flagged attributes are exported.');?></p>
                            <p><?php echo __('You can configure your tools to automatically download a file one of the Bro types.');?></p>

                            <div class="bg-light p-3 rounded border mb-4">
                                <pre class="mb-0"><code><?php
                                    foreach (array_keys($broTypes) as $broType) {
                                        echo $baseurl.'/attributes/bro/download/'.$broType . "\n";
                                    }
                                ?></code></pre>
                            </div>

                            <p><?php echo __('To restrict the results by tags, use the usual syntax. Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead). To get ip values from events tagged tag1 but not tag2 use');?>:</p>
                            <div class="bg-light p-2 rounded border mb-4">
                                <pre class="mb-0"><code><?php echo $baseurl.'/attributes/bro/download/ip/tag1&&!tag2'; ?></code></pre>
                            </div>

                            <hr class="my-4">
                            <h5 class="fw-bold mb-3"><?php echo __('Advanced Filters'); ?></h5>
                            <p><?php echo __('It is possible to restrict the bro exports based on a set of filters. POST a JSON object or an XML at the Bro API to filter the results.');?></p>

                            <span class="badge bg-primary mb-1">API Endpoint</span>
                            <pre class="bg-light p-2 rounded border mb-4"><code><?php echo $baseurl.'/attributes/bro/download'; ?></code></pre>

                            <div class="row g-4 mb-4">
                                <div class="col-md-6">
                                    <div class="card h-100 border-info">
                                        <div class="card-header bg-info text-dark fw-bold">XML Payload</div>
                                        <div class="card-body bg-light">
                                            <span class="text-muted small d-block mb-1">Headers:</span>
                                            <pre class="mb-3 small"><code><?php
                                                echo 'Authorization: ' . h($api_key) . PHP_EOL;
                                                echo 'Accept: application/json' . PHP_EOL;
                                                echo 'Content-type: application/json';
                                            ?></code></pre>
                                            <span class="text-muted small d-block mb-1">Body:</span>
                                            <pre class="mb-0 text-wrap"><code>&lt;request&gt;&lt;type&gt;ip&lt;/type&gt;&lt;eventid&gt;!51&lt;/eventid&gt;&lt;eventid&gt;!62&lt;/eventid&gt;&lt;withAttachment&gt;false&lt;/withAttachment&gt;&lt;tags&gt;APT1&lt;/tags&gt;&lt;tags&gt;!OSINT&lt;/tags&gt;&lt;from&gt;false&lt;/from&gt;&lt;to&gt;2015-02-15&lt;/to&gt;&lt;/request&gt;</code></pre>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="card h-100 border-warning">
                                        <div class="card-header bg-warning text-dark fw-bold">JSON Payload</div>
                                        <div class="card-body bg-light">
                                            <span class="text-muted small d-block mb-1">Headers:</span>
                                            <pre class="mb-3 small"><code><?php
                                                echo 'Authorization: ' . h($api_key) . PHP_EOL;
                                                echo 'Accept: application/json' . PHP_EOL;
                                                echo 'Content-type: application/json';
                                            ?></code></pre>
                                            <span class="text-muted small d-block mb-1">Body:</span>
                                            <pre class="mb-0 text-wrap"><code>{"request": {"type": "ip", "eventid": ["!51","!62"],"withAttachment": false,"tags": ["APT1","!OSINT"],"from": false,"to": "2015-02-15"}}</code></pre>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <p><?php echo __('Alternatively, it is also possible to pass the filters via the parameters in the URL, though it is highly advised to use POST requests with JSON objects instead. The format is as described below');?>:</p>
                            <div class="bg-light p-2 rounded border mb-4">
                                <pre class="mb-0"><code><?php echo $baseurl.'/attributes/bro/download/[type]/[tags]/[event_id]/[from]/[to]/[last]'; ?></code></pre>
                            </div>

                            <div class="row">
                                <div class="col-md-5">
                                    <h6 class="fw-bold text-primary">type:</h6>
                                    <p class="small text-muted mb-2"><?php echo __('The Bro type, any valid Bro type is accepted. The mapping between Bro and MISP types is as follows');?>:</p>
                                    <ul class="list-group list-group-sm mb-4">
                                        <?php foreach ($broTypes as $key => $value) { ?>
                                            <li class="list-group-item d-flex justify-content-between align-items-center py-1">
                                                <strong><?php echo h($key); ?></strong>
                                                <span class="badge bg-light text-dark border text-wrap"><?php echo h($value); ?></span>
                                            </li>
                                        <?php } ?>
                                    </ul>
                                </div>
                                <div class="col-md-7">
                                    <h6 class="fw-bold text-primary">Other Parameters:</h6>
                                    <dl class="row small mb-4">
                                        <dt class="col-sm-3 text-end"><span class="badge bg-secondary">tags</span></dt>
                                        <dd class="col-sm-9"><?php echo __('To include a tag in the results just write its names into this parameter. To exclude a tag prepend it with a \'!\'. You can also chain several tag commands together with the \'&amp;&amp;\' operator. Please be aware the colons (:) cannot be used in the tag search. Use semicolons instead (the search will automatically search for colons instead).');?></dd>

                                        <dt class="col-sm-3 text-end"><span class="badge bg-secondary">event_id</span></dt>
                                        <dd class="col-sm-9"><?php echo __('Restrict the results to the given event IDs.');?></dd>

                                        <dt class="col-sm-3 text-end"><span class="badge bg-secondary">allowNonIDS</span></dt>
                                        <dd class="col-sm-9"><?php echo __('Allow attributes to be exported that are not marked as "to_ids".');?></dd>

                                        <dt class="col-sm-3 text-end"><span class="badge bg-secondary">from</span></dt>
                                        <dd class="col-sm-9"><?php echo __('Events with the date set to a date after the one specified in the from field (format: 2015-02-15). This filter will use the date of the event.');?></dd>

                                        <dt class="col-sm-3 text-end"><span class="badge bg-secondary">to</span></dt>
                                        <dd class="col-sm-9"><?php echo __('Events with the date set to a date before the one specified in the to field (format: 2015-02-15). This filter will use the date of the event.');?></dd>

                                        <dt class="col-sm-3 text-end"><span class="badge bg-secondary">last</span></dt>
                                        <dd class="col-sm-9"><?php echo __('Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m). This filter will use the published timestamp of the event.');?></dd>

                                        <dt class="col-sm-3 text-end"><span class="badge bg-secondary">enforceWarninglist</span></dt>
                                        <dd class="col-sm-9"><?php echo __('All attributes that have a hit on a warninglist will be excluded.');?></dd>
                                    </dl>
                                </div>
                            </div>

                            <div class="alert alert-secondary mb-0">
                                <i class="fas fa-info-circle"></i> <?php echo __('The keywords false or null should be used for optional empty parameters in the URL.');?><br />
                                <?php echo __('For example, to retrieve all attributes for event #5, including non IDS marked attributes too, use the following line');?>:<br />
                                <code class="mt-2 d-inline-block bg-white p-1 rounded border"><?php echo $baseurl.'/attributes/text/download/all/null/5/true'; ?></code>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#xml">
                            Export attributes of event with specified type as XML
                        </button>
                    </h2>
                    <div id="xml" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <p class="small"><?php echo __('If you want to export all attributes of a predefined type that belong to an event, use the following syntax');?>:</p>
                            <div class="bg-light p-2 rounded border mb-3">
                                <pre class="mb-0 small"><code><?php echo $baseurl.'/attributes/returnAttributes/download/[id]/[type]/[sigOnly]'; ?></code></pre>
                            </div>
                            <p class="small text-muted mb-3">
                                <?php echo __('sigOnly is an optional flag that will block all attributes from being exported that don\'t have the IDS flag turned on. It is possible to search for several types with the \'&amp;&amp;\' operator and to exclude values with the \'!\' operator.');?>
                            </p>
                            <p class="small text-muted mb-3">
                                <?php echo __(' For example, to get all IDS signature attributes of type md5 and sha256, but not filename|md5 and filename|sha256 from event 25, use the following: ');?>
                            </p>
                            <p class="small fw-bold mb-1"><?php echo __('Example');?>: </p>
                            <div class="bg-light p-2 rounded border">
                                <pre class="mb-0 small text-wrap"><code><?php echo $baseurl.'/attributes/returnAttributes/download/25/md5&&sha256&&!filename/true';?></code></pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- SAMPLES TAB -->
        <div class="tab-pane fade" id="samples">
            <div class="accordion" id="samplesAccordion">

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button" data-bs-toggle="collapse" data-bs-target="#attachment">
                            Download attachment or malware sample
                        </button>
                    </h2>
                    <div id="attachment" class="accordion-collapse collapse show">
                        <div class="accordion-body">
                            <p class="small"><?php echo __('If you know the attribute ID of a malware-sample or an attachment, you can download it with the following syntax');?>:</p>
                            <div class="bg-light p-2 rounded border">
                                <pre class="mb-0 small text-wrap"><code><?php  echo $baseurl.'/attributes/downloadAttachment/download/[Attribute_id]';?></code></pre>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#hash">
                            Download malware sample by hash
                        </button>
                    </h2>
                    <div id="hash" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <p><?php echo __('You can also download samples by knowing its MD5 hash. Simply pass the hash along as a JSON/XML object or in the URL (with the URL having overruling the passed objects) to receive a JSON/XML object back with the zipped sample base64 encoded along with some contextual information.');?></p>
                            <p><?php echo __('You can also use this API to get all samples from events that contain the passed hash. For this functionality, just pass the "allSamples" flag along. Note that if you are getting all samples from matching events, you can use all supported hash types (%s) for the lookup.', h(implode(', ', $hashTypes)));?></p>
                            <p><?php echo __('You can also get all the samples from an event with a given event ID, by passing along the eventID parameter. Make sure that either an event ID or a hash is passed along, otherwise an error message will be returned. Also, if no hash is set, the allSamples flag will get set automatically.');?></p>

                            <div class="bg-light p-2 rounded border mb-4">
                                <pre class="mb-0"><code><?php echo $baseurl.'/attributes/downloadSample/[hash]/[allSamples]/[eventID]';?></code></pre>
                            </div>

                            <div class="row g-4 mb-4">
                                <div class="col-md-6">
                                    <div class="card h-100">
                                        <div class="card-header bg-info text-dark fw-bold small py-1"><?php echo __('POST message payload (XML)');?>:</div>
                                        <div class="card-body bg-light p-2">
                                            <pre class="mb-0 small text-wrap"><code><?php echo h("<request><hash>7c12772809c1c0c3deda6103b10fdfa0</hash><allSamples>1</allSamples><eventID>13</eventID</request>"); ?></code></pre>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="card h-100">
                                        <div class="card-header bg-warning text-dark fw-bold small py-1"><?php echo __('POST message payload (json)');?>:</div>
                                        <div class="card-body bg-light p-2">
                                            <pre class="mb-0 small text-wrap"><code>{"request": {"hash": "7c12772809c1c0c3deda6103b10fdfa0", "allSamples": 1, "eventID": 13}}</code></pre>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <h6 class="fw-bold mb-3"><?php echo __('A quick description of all the parameters in the passed object');?>:</h6>
                            <ul class="list-group list-group-flush mb-0">
                                <li class="list-group-item"><span class="badge bg-secondary">hash</span> : <?php echo __('A hash in MD5 format. If allSamples is set, this can be any one of the following: %s', h(implode(', ', $hashTypes)));?></li>
                                <li class="list-group-item"><span class="badge bg-secondary">allSamples</span> : <?php echo __('If set, it will return all samples from events that have a match for the hash provided above.');?></li>
                                <li class="list-group-item"><span class="badge bg-secondary">eventID</span> : <?php echo __('If set, it will only fetch data from the given event ID.');?></li>
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#upload">
                            Upload malware samples
                        </button>
                    </h2>
                    <div id="upload" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <div class="mb-4">
                                <span class="badge bg-primary mb-2">Endpoint</span>
                                <div class="bg-light p-2 rounded border">
                                    <pre class="mb-0 small"><code><?php echo $baseurl.'/events/upload_sample/[Event_id]';?></code></pre>
                                </div>
                            </div>

                            <div class="mb-4">
                                <p class="mb-2">
                                    <?php echo __('This API will allow you to populate an event that you have modify rights to with malware samples (and all related hashes). Alternatively, if you do not supply an event ID, it will create a new event for you.');?>
                                </p>
                                <p class="mb-2">
                                    <?php echo __('The files have to be base64 encoded and POSTed as explained below. All samples will be zipped and password protected (with the password being "infected"). The hashes of the original file will be captured as additional attributes.');?>
                                </p>
                                <p class="mb-0">
                                    <?php echo __('The event ID is optional. MISP will accept either a JSON or an XML object posted to the above URL.');?>
                                </p>
                            </div>

                            <hr class="my-4">

                            <h6 class="fw-bold text-primary mb-3">
                                <?php echo __('The general structure of the expected objects is as follows');?>
                            </h6>

                            <div class="bg-dark text-light p-3 rounded mb-4">
                                <pre class="mb-0 small text-wrap">
                        <code>{"request": {"files": [{"filename": "file1", "data": "base64"}, {"filename": "file2", "data": "base64"}], "optional_parameter1": "", "optional_parameter2": ""}}</code>
                                </pre>
                            </div>

                            <div class="row g-4 mb-4">
                                <div class="col-md-6">
                                    <div class="card h-100 border-info">
                                        <div class="card-header bg-info text-dark fw-bold small">
                                            XML Example
                                        </div>
                                        <div class="card-body bg-light p-3">
                                            <pre class="mb-0 small text-wrap"><code><?php echo h("<request><files><filename>test3.txt</filename><data>dGVzdA==</data></files><files><filename>test4.txt</filename><data>dGVzdDI=</data></files><info>test</info><distribution>1</distribution><event_id>15</event_id></request>");?></code></pre>
                                        </div>
                                    </div>
                                </div>

                                <div class="col-md-6">
                                    <div class="card h-100 border-warning">
                                        <div class="card-header bg-warning text-dark fw-bold small">
                                            JSON Example
                                        </div>
                                        <div class="card-body bg-light p-3">
                                            <pre class="mb-0 small text-wrap"><code>{"request":{"files":[{"filename":"test1.txt","data":"dGVzdA=="},{"filename":"test2.txt","data":"dGVzdDI="}],"distribution":1,"info":"test","event_id":15}}</code></pre>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <h6 class="fw-bold text-primary mb-3 mt-4">
                                <?php echo __('The following optional parameters are expected');?>
                            </h6>

                            <div class="card border-0 shadow-sm">
                                <div class="card-body p-3">
                                    <dl class="row mb-0 small">

                                        <dt class="col-sm-3">
                                            <span class="badge bg-secondary">event_id</span>
                                        </dt>
                                        <dd class="col-sm-9">
                                            <?php echo __('The Event\'s ID is optional. It can be either supplied via the URL or the POSTed object, but the URL has priority if both are provided.');?>
                                        </dd>

                                        <dt class="col-sm-3">
                                            <span class="badge bg-secondary">distribution</span>
                                        </dt>
                                        <dd class="col-sm-9">
                                            <?php echo __('The distribution setting used for the attributes and for the newly created event, if relevant. [0-3]');?>
                                        </dd>

                                        <dt class="col-sm-3">
                                            <span class="badge bg-secondary">to_ids</span>
                                        </dt>
                                        <dd class="col-sm-9">
                                            <?php echo __('You can flag all attributes created during the transaction to be marked as "to_ids" or not.');?>
                                        </dd>

                                        <dt class="col-sm-3">
                                            <span class="badge bg-secondary">category</span>
                                        </dt>
                                        <dd class="col-sm-9">
                                            <?php echo __('Valid options: Payload delivery, Artefacts dropped, Payload Installation, External Analysis.');?>
                                        </dd>

                                        <dt class="col-sm-3">
                                            <span class="badge bg-secondary">info</span>
                                        </dt>
                                        <dd class="col-sm-9">
                                            <?php echo __('Used to populate the event info field if no event ID supplied.');?>
                                        </dd>

                                        <dt class="col-sm-3">
                                            <span class="badge bg-secondary">analysis</span>
                                        </dt>
                                        <dd class="col-sm-9">
                                            <?php echo __('The analysis level of the newly created event. [0-2]');?>
                                        </dd>

                                        <dt class="col-sm-3">
                                            <span class="badge bg-secondary">threat_level_id</span>
                                        </dt>
                                        <dd class="col-sm-9">
                                            <?php echo __('The threat level ID. [0-3]');?>
                                        </dd>

                                        <dt class="col-sm-3">
                                            <span class="badge bg-secondary">comment</span>
                                        </dt>
                                        <dd class="col-sm-9">
                                            <?php echo __('Populates the comment field of created attributes.');?>
                                        </dd>
                                    </dl>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAGS TAB -->
        <div class="tab-pane fade" id="tags">
            <div class="accordion" id="tagsAccordion">

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button" data-bs-toggle="collapse" data-bs-target="#add">
                            Add or remove tags from events
                        </button>
                    </h2>
                    <div id="add" class="accordion-collapse collapse show">
                        <div class="accordion-body">
                            <p class="small"><?php echo __('You can add or remove an existing tag from an event in the following way');?>:</p>
                            <div class="bg-light p-2 rounded border mb-2">
                                <pre class="mb-0 small"><code><?php echo $baseurl.'/events/addTag'; ?></code></pre>
                            </div>
                            <div class="bg-light p-2 rounded border mb-3">
                                <pre class="mb-0 small"><code><?php  echo $baseurl.'/events/removeTag'; ?></code></pre>
                            </div>

                            <p class="small"><?php echo __('Just POST a json object in the following format (to the appropriate API depending on whether you want to add or delete a tag from an event)');?>:</p>
                            <div class="bg-light p-2 rounded mb-3">
                                <code class="small">{"event":228, "tag":8}</code>
                            </div>

                            <p class="small"><?php echo __('Where "tag" is the ID of the tag. You can also use a tag name the following way');?>:</p>
                            <div class="bg-light p-2 rounded">
                                <code class="small">{"event":228, "tag":"OSINT"}</code>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#proposals">
                            Proposals and the API
                        </button>
                    </h2>
                    <div id="proposals" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <p class="small text-muted"><?php echo __('You can interact with the proposals via the API directly since version 2.3.148');?></p>
                            <div class="table-responsive mb-4">
                                <table class="table table-hover table-striped table-bordered table-sm align-middle mb-0">
                                    <thead class="table-dark">
                                        <tr>
                                            <th><?php echo __('HTTP');?></th>
                                            <th><?php echo __('URL');?></th>
                                            <th><?php echo __('Explanation');?></th>
                                            <th><?php echo __('Expected Payload');?></th>
                                            <th><?php echo __('Response');?></th>
                                        </tr>
                                    </thead>
                                    <tbody class="small">
                                        <tr>
                                            <td><span class="badge bg-success">GET</span></td>
                                            <td><code>/shadow_attributes/view/[proposal_id]</code></td>
                                            <td><?php echo __('View a proposal');?></td>
                                            <td class="text-muted"><?php echo __('N/A');?></td>
                                            <td><?php echo __('ShadowAttribute object');?></td>
                                        </tr>
                                        <tr>
                                            <td><span class="badge bg-success">GET</span></td>
                                            <td><code>/shadow_attributes/index</code></td>
                                            <td><?php echo __('View all proposal of my org\'s events');?></td>
                                            <td class="text-muted"><?php echo __('N/A');?></td>
                                            <td><?php echo __('ShadowAttribute objects');?></td>
                                        </tr>
                                        <tr>
                                            <td><span class="badge bg-success">GET</span></td>
                                            <td><code>/shadow_attributes/index/[event_id]</code></td>
                                            <td><?php echo __('View all proposals of an event');?></td>
                                            <td class="text-muted"><?php echo __('N/A');?></td>
                                            <td><?php echo __('ShadowAttribute objects');?></td>
                                        </tr>
                                        <tr>
                                            <td><span class="badge bg-primary">POST</span></td>
                                            <td><code>/shadow_attributes/add/[event_id]</code></td>
                                            <td><?php echo __('Propose a new attribute to an event');?></td>
                                            <td><?php echo __('ShadowAttribute object');?></td>
                                            <td><?php echo __('ShadowAttribute object');?></td>
                                        </tr>
                                        <tr>
                                            <td><span class="badge bg-primary">POST</span></td>
                                            <td><code>/shadow_attributes/edit/[attribute_id]</code></td>
                                            <td><?php echo __('Propose an edit to an attribute');?></td>
                                            <td><?php echo __('ShadowAttribute object');?></td>
                                            <td><?php echo __('ShadowAttribute object');?></td>
                                        </tr>
                                        <tr>
                                            <td><span class="badge bg-primary">POST</span></td>
                                            <td><code>/shadow_attributes/accept/[proposal_id]</code></td>
                                            <td><?php echo __('Accept a proposal');?></td>
                                            <td class="text-muted"><?php echo __('N/A');?></td>
                                            <td><?php echo __('Message');?></td>
                                        </tr>
                                        <tr>
                                            <td><span class="badge bg-primary">POST</span></td>
                                            <td><code>/shadow_attributes/discard/[proposal_id]</code></td>
                                            <td><?php echo __('Discard a proposal');?></td>
                                            <td class="text-muted"><?php echo __('N/A');?></td>
                                            <td><?php echo __('Message');?></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>

                            <p class="small fw-bold mb-2"><?php echo __('When posting a shadow attribute object, use the following formats');?></p>
                            <div class="row g-2">
                                <div class="col-12 mt-3">
                                    <span class="badge bg-info text-dark">XML</span>
                                    <div class="bg-light p-2 rounded border mt-1">
                                        <pre class="mb-0 small text-wrap"><code><?php echo h('<request><ShadowAttribute><value>5.5.5.5</value><to_ids>0</to_ids><type>ip-src</type><category>Network activity</category></ShadowAttribute></request>');?></code></pre>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <span class="badge bg-warning text-dark">JSON</span>
                                    <div class="bg-light p-2 rounded border mt-1">
                                        <pre class="mb-0 small text-wrap"><code><?php echo h('{"request": {"ShadowAttribute": {"value": "5.5.5.5", "to_ids": false, "type": "ip-dst", "category": "Network activity"}}}');?></code></pre>
                                    </div>
                                </div>
                            </div>
                            <p class="small text-muted mt-2 mb-0"><i class="fas fa-info-circle"></i> <?php echo __('None of the above fields are mandatory, but at least one of them has to be provided.');?></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- AUTOMATION TAB -->
        <div class="tab-pane fade" id="automation">
            <div class="accordion" id="automationAccordion">

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button" data-bs-toggle="collapse" data-bs-target="#freetext">
                            Freetext Import API
                        </button>
                    </h2>
                    <div id="freetext" class="accordion-collapse collapse show">
                        <div class="accordion-body">
                            <?php
                                $data = array(
                                    'title' => __('Freetext Import API'),
                                    'description' => array(
                                        __('The freetext import tool is also exposed to the API.'),
                                        __('Simply POST the contents to be parsed and either directly create attributes out of them or simply return the parsing results.'),
                                        __('Use the boolean (0/1) adhere_to_warninglists and return_meta_attributes url parameters to filter out values tripping over a warninglist and to decide whether to save the attributes parsed or simply return them as meta attributes.'),
                                        __('The contents of the POST body should be the text to be parsed.')
                                    ),
                                    'url' => array(
                                        $baseurl . '/[event_id]/[adhere_to_warninglists]/[return_meta_attributes]'
                                    )
                                );
                            ?>
                            <p><?php echo implode(" ", $data['description']); ?></p>
                            <div class="bg-light p-3 rounded border">
                                <pre class="mb-0"><code><?php echo implode("\n", $data['url']); ?></code></pre>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#params">
                            URL parameters
                        </button>
                    </h2>
                    <div id="params" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <p class="card-text text-danger fw-bold">
                                <i class="fas fa-exclamation-circle"></i> 
                                <?php echo __('It is also possible to pass all of the above parameters via URL parameters, however this is HIGHLY discouraged. If you however have no other options, simply pass the parameters in the following fashion:'); ?>
                            </p>
                            <div class="bg-light p-2 rounded border mb-3">
                                <pre class="mb-0 text-break" style="white-space: pre-wrap;"><code><?php echo $baseurl . '/attributes/restSearch/returnFormat:text/tags:!tlp:red||!tlp:amber||tlp:green||tlp:white/publish_timestamp:14d||7d'; ?></code></pre>
                            </div>
                            <p class="card-text small text-muted">
                                <?php echo __('As you can see above, "||" can be used to add more values to a "list" and all parameters are passed as key:value components to the URL. Keep in mind, certain special characters in URLs can cause issues, your searches may end up being leaked to logs in transit and there are length limitations to take into account. Use this as a last resort.'); ?>
                            </p>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" data-bs-toggle="collapse" data-bs-target="#notification">
                            Setting up the periodic notification scheduled task
                        </button>
                    </h2>
                    <div id="notification" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <p><?= __('The current recommendation to schedule periodic tasks in MISP is to use CRON jobs.') ?></p>
                            <p><?= __('The %s functionality takes care of sending daily, weekly and monthly summaries. As this process is resource intensive, it\'s heavily recommended to run it once per day. But more importantly, spamming recipients\' mailbox will undermine their trust and willingness to participate in the community. As such, in order for site-admins to keep running a thriving community, they are advised to make sure their system configuration and behaviours stays inclusive, open, collaborative and enjoyable to all members.', sprintf('<code>%s</code>', 'sendPeriodicSummaryToUsers')) ?></p>

                            <p class="fw-bold mt-4"><?= __('The command below is a recommendation on how the CRON entry should look like. This entry executes the command each day at 06:00 AM. Daily mails will be sent. Weekly mails are sent on Mondays. Monthly mails are sent on the 1st of each month.') ?></p>
                            <div class="bg-light p-3 rounded mb-4">
                                <code class="text-break" style="white-space: pre-wrap;">0 6 * * * /var/www/MISP/app/Console/cake Server sendPeriodicSummaryToUsers >/dev/null 2>&1 # Send daily, weekly and monthly summary when appropriate</code>
                            </div>

                            <ul class="list-group list-group-flush mb-0 border rounded">
                                <li class="list-group-item">
                                    <i class="fas fa-chart-bar text-primary me-2"></i> 
                                    <?= __('Users can visualize the output that would be generated by accessing %s.', sprintf('<a href="%s" class="fw-bold text-decoration-none">%s</a>', $baseurl . '/users/viewPeriodicSummary/daily', __('their periodic summary'))) ?>
                                </li>
                                <li class="list-group-item">
                                    <i class="fas fa-cogs text-primary me-2"></i> 
                                    <?= __('Users can edit their setting by accessing %s.', sprintf('<a href="%s" class="fw-bold text-decoration-none">%s</a>', $baseurl . '/users/notificationSettings', __('their periodic notification settings'))) ?>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>


        <!-- CLI TAB -->
        <div class="tab-pane fade" id="cli">
            <div class="accordion" id="cliAccordion">

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button" data-bs-toggle="collapse" data-bs-target="#admin">
                            Administering the background workers via the API.
                        </button>
                    </h2>
                    <div id="admin" class="accordion-collapse collapse show">
                        <div class="accordion-body">
                            <?php
                                $data = array(
                                    'title' => __('Administering the background workers via the API.'),
                                    'description' => array(
                                        __('You can start/stop and view the background workers via the API.'),
                                        sprintf('<span class="fw-bold text-success">%s</span>: <code>%s/servers/%s</code>', __('Add worker'), $baseurl, 'startWorker/[queue_name]'),
                                        sprintf('<span class="fw-bold text-danger">%s</span>: <code>%s/servers/%s</code>', __('Stop worker'), $baseurl, 'stopWorker/[worker_pid]'),
                                        sprintf('<span class="fw-bold text-info">%s</span>: <code>%s/servers/%s</code>', __('Get worker info'), $baseurl, 'getWorkers')
                                    )
                                );
                            ?>
                            <p><?php echo $data['description'][0]; ?></p>
                            <div class="bg-light p-3 rounded border mb-4">
                                <ul class="list-unstyled mb-0">
                                    <li class="mb-2"><?php echo $data['description'][1]; ?></li>
                                    <li class="mb-2"><?php echo $data['description'][2]; ?></li>
                                    <li><?php echo $data['description'][3]; ?></li>
                                </ul>
                            </div>

                            <hr class="my-4">

                            <?php foreach ($command_line_functions as $clusterRef => $cluster): ?>
                                <a id="<?php echo $clusterRef; ?>"></a>
                                <h4 class="fw-bold text-primary mt-4 mb-2"><?php echo $cluster['header']; ?></h4>
                                <p class="text-muted mb-3"><?php echo $cluster['description']; ?>:</p>
                                <div class="table-responsive mb-4">
                                    <table class="table table-bordered table-striped table-sm">
                                        <tbody>
                                            <?php foreach ($cluster['data'] as $commandName => $command): ?>
                                                <tr>
                                                    <td class="fw-bold" style="width: 30%;"><?php echo Inflector::humanize($commandName); ?></td>
                                                    <td><code class="text-dark bg-light px-2 py-1 rounded border"><?php echo $command; ?></code></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>