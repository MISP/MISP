<?php

/**
 * Dashboard administration from the CLI.
 *
 * `importDefaultTemplates` mirrors the gallery's site-admin import action
 * (DD-22): it ingests the built-in dashboard templates shipped under
 * app/files/dashboard-templates/ into the `dashboards` table as
 * selectable, system-owned (user_id 0) starter templates. Idempotent —
 * each template is upserted on its fixed uuid, so re-running refreshes
 * the shipped rows from the files without duplicating them. As the
 * explicit operator-triggered ingest it also prunes orphaned built-ins
 * (rows whose manifest no longer ships); the silent auto-ingest on
 * update (DD-24) does not.
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
        // $prune = true: this is the explicit operator-triggered ingest, so
        // built-ins whose manifest no longer ships are pruned (the silent
        // auto-ingest on update, DD-24, leaves them be).
        $result = $this->Dashboard->importTemplatesFromDirectory(null, true);
        foreach ($result['success'] as $id => $success) {
            $this->out(sprintf('  [OK]   %s (#%d)', $success['name'], $id));
        }
        foreach ($result['fails'] as $slug => $message) {
            $this->err(sprintf('  [FAIL] %s: %s', $slug, $message));
        }
        $pruned = isset($result['pruned']) ? $result['pruned'] : array();
        foreach ($pruned as $id => $name) {
            $this->out(sprintf('  [PRUNE] %s (#%d) — no longer shipped', $name, $id));
        }
        if (!empty($result['promoted_default'])) {
            foreach ($result['promoted_default'] as $id => $name) {
                $this->out(sprintf('  [DEFAULT] %s (#%d) — promoted (instance had no default)', $name, $id));
            }
        }
        $this->out(sprintf(
            '%d built-in dashboard template(s) imported, %d failed, %d orphaned pruned.',
            count($result['success']),
            count($result['fails']),
            count($pruned)
        ));
    }
}
