<?php

$notificationTypes = [
    'autoalert' => __('Event published notification'),
    'notification_daily' => __('Daily notifications'),
    'notification_weekly' => __('Weekly notifications'),
    'notification_monthly' => __('Monthly notifications'),
];
$notificationsHtml = '<table>';

foreach ($notificationTypes as $notificationType => $description) {
    $isEnabled = !empty($entity[$notificationType]);
    $boolean = sprintf(
        '<span class="%s">%s</span>',
            $isEnabled ? 'badge bg-success' : 'badge bg-danger',
        $isEnabled ? __('Yes') : __('No'));
    $notificationsHtml .= '<tr><td>' . $description . '</td><td>' . $boolean . '</td>';
}
$notificationsHtml .= '</table>';
echo $notificationsHtml;