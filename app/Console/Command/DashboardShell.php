<?php

/**
 * Dashboard administration from the CLI.
 *
 * `importDefaultTemplates` mirrors the gallery's site-admin import action
 * (DD-22): it ingests the built-in dashboard templates shipped under
 * app/files/dashboard-templates/ into the `dashboards` table as
 * selectable, system-owned (user_id 0) starter templates. Idempotent —
 * each template is upserted on its fixed uuid, so re-running refreshes
 * the shipped rows from the files without duplicating them.
 */
class DashboardShell extends AppShell
{
    public $uses = array('Dashboard');

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('importDefaultTemplates', array(
            'help' => __('Import the built-in dashboard templates shipped under app/files/dashboard-templates/ into the template gallery.'),
        ));
        return $parser;
    }

    public function importDefaultTemplates()
    {
        $result = $this->Dashboard->importTemplatesFromDirectory();
        foreach ($result['success'] as $id => $success) {
            $this->out(sprintf('  [OK]   %s (#%d)', $success['name'], $id));
        }
        foreach ($result['fails'] as $slug => $message) {
            $this->err(sprintf('  [FAIL] %s: %s', $slug, $message));
        }
        $this->out(sprintf(
            '%d built-in dashboard template(s) imported, %d failed.',
            count($result['success']),
            count($result['fails'])
        ));
    }
}
