<?php
    echo '<div class="index">';
    echo $this->element('/genericElements/IndexTable/index_table', array(
        'data' => array(
            'data' => $data,
            'top_bar' => array(
                'children' => array(
                    array(
                        'children' => array(
                            array(
                                'fa-icon' => 'check',
                                'title' => __('Process the selected registrations'),
                                'id' => 'multi-accept-button',
                                'class' => 'btn btn-small btn-inverse mass-select hidden'
                            ),
                            array(
                                'fa-icon' => 'times',
                                'title' => __('Discard the selected registrations'),
                                'id' => 'multi-discard-button',
                                'class' => 'btn btn-small btn-inverse mass-select hidden'
                            )
                        )
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
                    'element' => 'selector',
                    'class' => 'short'
                ),
                array(
                    'name' => __('Id'),
                    'class' => 'short',
                    'data_path' => 'Inbox.id',
                ),
                array(
                    'name' => __('Time'),
                    'class' => 'short',
                    'element' => 'timestamp',
                    'time_format' => 'Y-m-d H:i:s',
                    'data_path' => 'Inbox.timestamp',
                ),
                array(
                    'name' => __('IP'),
                    'class' => 'short',
                    'data_path' => 'Inbox.ip',
                ),
                array(
                    'name' => __('User Agent'),
                    'class' => 'shortish',
                    'data_path' => 'Inbox.user_agent',
                ),
                array(
                    'name' => __('Email'),
                    'class' => 'short',
                    'data_path' => 'Inbox.data.email',
                ),
                array(
                    'name' => __('Org'),
                    'class' => 'short',
                    'data_path' => 'Inbox.data.org_name',
                ),
                array(
                    'name' => __('Org uuid'),
                    'class' => 'shortish',
                    'data_path' => 'Inbox.data.org_uuid',
                ),
                array(
                    'name' => __('Requested role'),
                    'class' => 'short',
                    'element' => 'list',
                    'data_path' => 'Inbox.requested_role',
                ),
                array(
                    'name' => __('PGP'),
                    'class' => 'short',
                    'element' => 'boolean',
                    'data_path' => 'Inbox.data.pgp'
                ),
                array(
                    'name' => __('Comment'),
                    'data_path' => 'Inbox.comment',
                )
            ),
            'title' => __('Registrations index'),
            'description' => __('You can find messages sent to this instance in the following list. Type denotes the type of request (such as registration). View each entry to see more details about the request\'s contents.'),
            'actions' => array(
                array(
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/users/acceptRegistrations/[onclick_params_data_path]\')',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'Inbox.id',
                    'icon' => 'check',
                    'title' => __('Process registration')
                ),
                array(
                    'onclick' => sprintf(
                        'openGenericModal(\'%s/users/discardRegistrations/[onclick_params_data_path]\')',
                        $baseurl
                    ),
                    'onclick_params_data_path' => 'Inbox.id',
                    'icon' => 'times',
                    'title' => __('Discard registration')
                )
            )
        )
    ));
    echo '</div>';
    echo $this->element('/genericElements/SideMenu/side_menu', array('menuList' => 'admin', 'menuItem' => 'registrations'));
?>
<script type="text/javascript">
    var passedArgsArray = <?php echo $passedArgs; ?>;

    function handleInboxMultiActions(action) {
        var selectedInboxIds = '';
        $.each($('.select_attribute:checked'), function() {
            selectedInboxIds += "/id[]:" + ($(this).parent().parent().find('[data-path="Inbox.id"]').text());
        });
        if (selectedInboxIds.length >= 1) {
            openGenericModal(baseurl + "/users/" + action + selectedInboxIds)
        }
    }
    $(document).ready(function() {
        $('#multi-accept-button').on('click', function() {
            handleInboxMultiActions("acceptRegistrations");
        });
        $('#multi-discard-button').on('click', function() {
            handleInboxMultiActions("discardRegistrations");
        });
        $('#quickFilterButton').click(function() {
            runIndexQuickFilter();
        });
    });
</script>
