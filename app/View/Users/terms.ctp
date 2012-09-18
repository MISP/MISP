<div class="users form">
<h2>CyDefSIG Terms and Conditions</h2>
<p><i>CyDefSIG is a platform for a trusted official service to share Malware signatures with the Belgian Defence ADIV/SGRS.</i></p>
<p>As a member of CyDefSIG you accept all the following:</p>
<ul>
<li>Members accept their intention to share signature information <small>(about new/unknown malware and attacks they have detected)</small> into the CyDefSIG system.</li>
<li>All information from CyDefSIG must be treated as Unclassified or Restricted <em>only releasable to the CyDefSIG registered parties</em> (comparable to TLP amber), and should thus <em>never be further distributed without prior approval by the publishing party</em>.</li>
<li>Members are required to report any known security issue or vulnerability with the CyDefSIG system to the Belgian Defence ADIV/SGRS.</li>
<li>CyDefSIG may be terminated by either Party by giving the other Party a seven (7) days notice. Shared information can never be reclaimed.</li>
<li>Only the following service can be contacted concerning CyDefSIG : ADIV/SGRS, INFOSEC, Everestraat 1, 1140 Brussels, Belgium, +32 2 701 36 26, infosec@qet.be</li>
</ul>
&nbsp;
<h3>Disclaimer of Warranty.</h3>
<ul><li>There is no warranty for the system, to the extent permitted by applicable law.
The Belgian Defence and services provide the system "as is" without warranty of any kind,
 either expressed or implied, including, but not limited to, the implied warranties of
 merchantability and fitness for a particular purpose. The entire risk as to the quality
 and performance of the system is with you (any user of the system).
 Should the system prove defective, you any user of the system, assume all your resulting
 costs and consequences.</li></ul>
&nbsp;
<h3>Limitation of liability.</h3>
<ul>
<li>No Party or its affiliates, agents or representatives shall be liable to the other Party
or its affiliates agents or representatives for any indirect, incidental, consequential,
exemplary, punitive or special damages in connection with anything that is undertaken by the
parties under the use of this system, or anything arising out of this use. This Section
applies to the maximum extent permitted by applicable law and regardless of whether the liability
is based on breach of these terms, tort, or any other legal theory</li>
<li>In no event will the Belgian Defence, or any other party providing the system, be liable
to you (any user of the system) for damages, including any general, special, incidental or
consequential damages arising out of the use or inability to use the system (including but
not limited to loss of data or data being rendered inaccurate or losses sustained by you or
third parties or a failure of the system to operate with any other systems), even if such
holder or other party has been advised of the possibility of such damages.</li>
</ul>


<?php
if (!$termsaccepted) {
    echo $this->Form->create('User');
    echo $this->Form->hidden('termsaccepted', array('default'=> '1'));
    echo $this->Form->end(__('Accept Terms', true));
}
?>
</div>

<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
<script type="text/javascript">
$('#button_off').click(function() {
	return false;
});
</script>
