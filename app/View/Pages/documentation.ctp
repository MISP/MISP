<div class="index">
<h2>Documentation</h2>
<p>
</p>


<h2>Export and Import</h2>
<p>CyDefSIG has full support for automated data export and import.</p>
<h3>IDS and script export</h3>
<p>First of all you can export data in formats that are suitable for NIDS or scripts (text, xml,...).<br/>
All details about this export can be found on the <?php echo $this->Html->link(__('Export', true), array('controller' => 'events', 'action' => 'export')); ?> page.
</p>
<h3>REST API</h3>
<p>CydefSIG is also <a href="http://en.wikipedia.org/wiki/Representational_state_transfer">RESTfull</a>, so this means you can use structured format (XML) to access Events data.</p>
<h4>Requests</h4>
<p>Use any HTTP compliant library to perform requests. However to make clear you are doing a REST request you need to either specify the <code>Accept</code> type to <code>application/xml</code>, or append <code>.xml</code> to the url.</p>
<p>The following table shows the relation of the request type and the resulting action:</p>
<table style="width:250px;">
<colgroup>
<col width="18%">
<col width="34%">
<col width="48%">
</colgroup>
<thead valign="bottom">
<tr><th class="head">HTTP format</th>
<th class="head">URL</th>
<th class="head">Controller action invoked</th>
</tr>
</thead>
<tbody valign="top">
<tr><td>GET</td>
<td>/events</td>
<td>EventsController::index() <sup>(1)</sup></td>
</tr>
<tr><td>GET</td>
<td>/events/123</td>
<td>EventsController::view(123) <sup>(2)</sup></td>
</tr>
<tr><td>POST</td>
<td>/events</td>
<td>EventsController::add()</td>
</tr>
<tr><td>PUT</td>
<td>/events/123</td>
<td>EventsController::edit(123)</td>
</tr>
<tr><td>DELETE</td>
<td>/events/123</td>
<td>EventsController::delete(123)</td>
</tr>
<tr><td>POST</td>
<td>/events/123</td>
<td>EventsController::edit(123)</td>
</tr>
</tbody>
</table>
<small>(1) Warning, there's a limit on the number of results when you call <code>index</code>.</small><br/>
<small>(2) Attachments are included using base64 encoding below the <code>data</code> tag.</small><br/>
<br/>

<h4>Authentication</h4>
<p>REST being stateless you need to authenticate your request by using your <?php echo $this->Html->link(__('authkey/apikey', true), array('controller' => 'users', 'action' => 'view', 'me')); ?>. Simply set the <code>Authorization</code> HTTP header.</p>
<h4>Example - Get single Event</h4>
<p>In this example we fetch the details of a single Event (and thus also his Attributes).<br/>
The request should be:</p>
<pre>GET <?php echo Configure::read('CyDefSIG.baseurl');?>/events/123</pre>
<p>And with the HTTP Headers:</p>
<pre>Accept: application/xml
Authorization: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</pre>
<p>The response you're going to get is the following data:</p>
<pre>&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot; standalone=&quot;no&quot;?&gt;
&lt;response&gt;
    &lt;Event&gt;
        &lt;id&gt;123&lt;/id&gt;
        &lt;date&gt;2012-04-06&lt;/date&gt;
        &lt;risk&gt;Undefined&lt;/risk&gt;
        &lt;info&gt;TEST&lt;/info&gt;
        &lt;published&gt;0&lt;/published&gt;
        &lt;uuid&gt;4f7eff11-4e98-47b7-ae96-6a7fff32448e&lt;/uuid&gt;
        &lt;private&gt;0&lt;/private&gt;
        &lt;Attribute&gt;
            &lt;id&gt;9577&lt;/id&gt;
            &lt;event_id&gt;123&lt;/event_id&gt;
            &lt;category&gt;Artifacts dropped&lt;/category&gt;
            &lt;type&gt;other&lt;/type&gt;
            &lt;value&gt;test other&lt;/value&gt;
            &lt;to_ids&gt;1&lt;/to_ids&gt;
            &lt;uuid&gt;4f7fe870-e5a4-4b9e-a89c-a45bff32448e&lt;/uuid&gt;
            &lt;revision&gt;1&lt;/revision&gt;
            &lt;private&gt;0&lt;/private&gt;
        &lt;/Attribute&gt;
        &lt;Attribute&gt;
            &lt;id&gt;9576&lt;/id&gt;
            &lt;event_id&gt;123&lt;/event_id&gt;
            &lt;category&gt;Payload delivery&lt;/category&gt;
            &lt;type&gt;filename&lt;/type&gt;
            &lt;value&gt;test attribute&lt;/value&gt;
            &lt;to_ids&gt;1&lt;/to_ids&gt;
            &lt;uuid&gt;4f7fe85b-0f78-4e40-91f3-a45aff32448e&lt;/uuid&gt;
            &lt;revision&gt;1&lt;/revision&gt;
            &lt;private&gt;0&lt;/private&gt;
        &lt;/Attribute&gt;
    &lt;/Event&gt;
&lt;/response&gt;</pre>


<h4>Example - Add new Event</h4>
<p>In this example we want to add a single Event.<br/>
The request should be:</p>
<pre>POST <?php echo Configure::read('CyDefSIG.baseurl');?>/events
Accept: application/xml
Authorization: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</pre>
<p>And the request body:</p>
<pre>&lt;Event&gt;
    &lt;date&gt;2012-05-06&lt;/date&gt;
    &lt;risk&gt;Undefined&lt;/risk&gt;
    &lt;info&gt;TEST REST&lt;/info&gt;
    &lt;published&gt;0&lt;/published&gt;
    &lt;private&gt;0&lt;/private&gt;
    &lt;attribute/&gt;
&lt;/Event&gt;</pre>
<p>The response you're going to get is the following data:</p>
<h2>FIXME </h2>



<h4>Example - Requesting an invalid page</h4>
<h2>FIXME </h2>



</div>

<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

