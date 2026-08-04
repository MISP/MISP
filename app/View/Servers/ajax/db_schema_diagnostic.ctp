<?php echo $this->element('/healthElements/db_schema_diagnostic', array(
    'checkedTableColumn' => $dbSchemaDiagnostics['checked_table_column'],
    'dbSchemaDiagnostics' => $dbSchemaDiagnostics['diagnostic'],
    'expectedDbVersion' => $dbSchemaDiagnostics['expected_db_version'],
    'actualDbVersion' => $dbSchemaDiagnostics['actual_db_version'],
    'error' => $dbSchemaDiagnostics['error'],
    'remainingLockTime' => $dbSchemaDiagnostics['remaining_lock_time'],
    'updateFailNumberReached' => $dbSchemaDiagnostics['update_fail_number_reached'],
    'updateLocked' => $dbSchemaDiagnostics['update_locked']
)); ?>