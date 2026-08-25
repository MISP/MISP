<?php
/**
 * Overmind "Delete user" confirmation modal.
 * Rendered body-only by UsersController::admin_delete() on ajax + Overmind
 * (opened via openModal from the user profile Quick action card).
 * $targetUser = ['User' => ['id', 'email']].
 */
$uid = $targetUser['User']['id'];
// NB: do NOT seed request->data['User']['id'] here — that makes FormHelper treat
// the form as an edit and emit _method=PUT, which admin_delete (post/delete only)
// ignores → the modal reloads without deleting. A create-style form posts as POST.
// admin_delete reads the id from the URL anyway.

echo $this->element('genericElementsBS5/Modals/delete_confirmation_form', [
    'title'   => __('Delete user'),
    'model'   => 'User',
    'url'     => $baseurl . '/admin/users/delete/' . h($uid),
    'message' => __(
        'Are you sure you want to delete %s? It is strongly recommended to disable the user instead of deleting them.',
        h($targetUser['User']['email'])
    ),
]);
