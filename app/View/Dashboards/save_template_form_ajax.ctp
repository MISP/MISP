<?php
/**
 * Layout-less render of the save/edit dashboard-template form, for the
 * dashboard slide-in panel. Served by DashboardsController::saveTemplate when
 * the GET is an XHR ($this->request->is('ajax')); save-template.module.mjs
 * fetches it and injects it into the shared configure panel body. The form
 * (incl. its CSRF token) is the shared element — identical to the full-page
 * flow, so the existing POST handling round-trips unchanged.
 */
echo $this->element('dashboard/save_template_form');
