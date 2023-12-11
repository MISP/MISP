<?php
/*
 *  echo $this->element('/genericElements/IndexTable/index_table', array(
 *      'top_bar' => (
 *          // search/filter bar information compliant with ListTopBar
 *      ),
 *      'data' => array(
            // the actual data to be used
 *      ),
 *      'fields' => array(
 *          // field list with information for the paginator
 *      ),
 *      'title' => optional title,
 *      'description' => optional description
 *  ));
 *
 */
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $delegation_requests,
            'top_bar' => array(
                'children' => array(
                    array(
                        'type' => 'simple',
                        'children' => array(
                            array(
                                'active' => $context === 'pending',
                                'url' => $baseurl . '/event_delegations/index/context:pending',
                                'text' => __('Pending'),
                            ),
                            array(
                                'active' => $context === 'issued',
                                'url' => $baseurl . '/event_delegations/index/context:issued',
                                'text' => __('Issued'),
                            )
                        ),
                    ),
                    array(
                        'type' => 'search',
                        'button' => __('Filter'),
                        'placeholder' => __('Enter value to search'),
                        'data' => '',
                        'searchKey' => 'value'
                    )
                )
            ),
            'fields' => array(
                array(
                    'name' => __('Id'),
                    'sort' => 'EventDelegation.id',
                    'class' => 'short',
                    'data_path' => 'EventDelegation.id',
                ),
                array(
                    'name' => __('Requester'),
                    'class' => 'short',
                    'element' => 'org',
                    'sort' => 'EventDelegation.requester_org_id',
                    'data_path' => 'EventDelegation.RequesterOrg'
                ),
                array(
                    'name' => __('Recipient'),
                    'class' => 'short',
                    'element' => 'org',
                    'sort' => 'EventDelegation.org_id',
                    'data_path' => 'EventDelegation.Org'
                ),
                array(
                    'name' => __('Event id'),
                    'sort' => 'EventDelegation.event_id',
                    'element' => 'links',
                    'class' => 'short',
                    'data_path' => 'EventDelegation.event_id',
                    'url' => $baseurl . '/events/view/%s'
                ),
                array(
                    'name' => __('Event info'),
                    'data_path' => 'EventDelegation.Event.info'
                ),
                array(
                    'name' => __('Message'),
                    'data_path' => 'EventDelegation.message'
                )
            ),
            'title' => __('Delegation index'),
            'description' => __('')
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'event-collection', 'menuItem' => 'viewDelegations'));
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;
    if (passedArgsArray['context'] === undefined) {
        passedArgsArray['context'] = 'pending';
    }
    $(document).ready(function() {
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter('/context:' + passedArgsArray['context']);
        });
    });
</script>
