<?php

class MispStatusWidget
{
    public $title = 'MISP Status';
    public $render = 'SimpleList';
    public $width = 2;
    public $height = 2;
    public $params = array();
    public $description = 'Basic widget showing some user related MISP notifications.';


	public function handler($user, $options = array())
	{
        $this->Event = ClassRegistry::init('Event');
        // the last login in the session is not updated after the login - only in the db, so let's fetch it.
        $lastLogin = $user['last_login'];
        $data = array();
        $data[] = array(
            'title' => __('Events modified'),
            'value' => count(
                $this->Event->fetchEventIds($user, [
                    'list' => true,
                    'timestamp' => $lastLogin
                ])
            ),
            'html' => sprintf(
                ' (<a href="%s">%s</a>)',
                Configure::read('MISP.baseurl') . '/events/index/timestamp:' . (time() - 86400),
                'View'
            )
        );
        $data[] = array(
            'title' => __('Events published'),
            'value' => count(
                $this->Event->fetchEventIds($user, [
                    'list' => true,
                    'publish_timestamp' => $lastLogin
                ])
            ),
            'html' => sprintf(
                ' (<a href="%s">%s</a>)',
                Configure::read('MISP.baseurl') . '/events/index/published:1/timestamp:' . (time() - 86400),
                'View'
            )
        );
        $notifications = $this->Event->populateNotifications($user);
        if (!empty($notifications['proposalCount'])) {
            $data[] = array(
                'title' => __('Pending proposals'),
                'value' => $notifications['proposalCount'],
                'html' => sprintf(
                    ' (<a href="%s">%s</a>)',
                    Configure::read('MISP.baseurl') . '/shadow_attributes/index/all:0',
                    'View'
                )
            );
        }
        if (!empty($notifications['proposalEventCount'])) {
            $data[] = array(
                'title' => __('Events with proposals'),
                'value' => $notifications['proposalEventCount'],
                'html' => sprintf(
                    ' (<a href="%s">%s</a>)',
                    Configure::read('MISP.baseurl') . '/events/proposalEventIndex',
                    'View'
                )
            );
        }
        if (!empty($notifications['delegationCount'])) {
            $data[] = array(
                'title' => __('Delegation requests'),
                'value' => $notifications['delegationCount'],
                'html' => sprintf(
                    ' (<a href="%s">%s</a>)',
                    Configure::read('MISP.baseurl') . '/event_delegations/index/context:pending',
                    'View'
                )
            );
        }
        return $data;
	}
}
