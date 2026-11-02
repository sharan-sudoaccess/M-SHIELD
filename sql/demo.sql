-- =============================================================================
-- M-SHIELD : demo.sql  —  guided LIVE DEMO script
-- Run AFTER 01→04 are loaded (schema + data + views + triggers).
-- Each step prints a banner naming the DBMS concept it demonstrates.
-- Suggested invocation (nice boxed output):
--   mysql -u <user> -p --table mshield < sql/demo.sql
-- =============================================================================
USE mshield;

SELECT '========================================================' AS `M-SHIELD LIVE DEMO`;

-- -----------------------------------------------------------------------------
SELECT '1. SCHEMA  — eight normalized (3NF) tables' AS `STEP`;
SHOW TABLES;

-- -----------------------------------------------------------------------------
SELECT '2. SAMPLE DATA — devices and their installed apps (1:N join)' AS `STEP`;
SELECT d.name AS device, d.os_type, a.app_name, a.publisher
FROM device d
JOIN application a ON a.device_id = d.device_id
ORDER BY d.name, a.app_name;

-- -----------------------------------------------------------------------------
SELECT '3. FLAGSHIP JOIN — device -> app -> vuln -> incident -> analyst (5 tables)' AS `STEP`;
SELECT d.name AS device, a.app_name, v.severity,
       v.title AS vulnerability, i.status,
       COALESCE(an.name,'(unassigned)') AS analyst
FROM incident i
JOIN vulnerability v ON v.vuln_id   = i.vuln_id
JOIN application   a ON a.app_id    = v.app_id
JOIN device        d ON d.device_id = a.device_id
LEFT JOIN analyst  an ON an.analyst_id = i.assigned_analyst_id
ORDER BY FIELD(v.severity,'Critical','High','Medium','Low'), d.name;

-- -----------------------------------------------------------------------------
SELECT '4. VIEW — apps requesting HIGH-risk permissions (M:N relationship)' AS `STEP`;
SELECT * FROM v_apps_with_risky_permissions
ORDER BY risky_permission_count DESC;

-- -----------------------------------------------------------------------------
SELECT '5. AGGREGATION — vulnerabilities grouped by severity' AS `STEP`;
SELECT severity, COUNT(*) AS vuln_count
FROM vulnerability
GROUP BY severity
ORDER BY FIELD(severity,'Critical','High','Medium','Low');

SELECT '   AGGREGATION — incidents handled per analyst (LEFT JOIN)' AS `STEP`;
SELECT * FROM v_analyst_workload ORDER BY total_incidents DESC;

-- -----------------------------------------------------------------------------
SELECT '6. TRIGGER DEMO — watch INCIDENT_HISTORY fill automatically' AS `STEP`;

SELECT '   (a) Incident 7 BEFORE any change:' AS `STEP`;
SELECT incident_id, title, status, resolved_at FROM incident WHERE incident_id = 7;
SELECT history_id, action, old_status, new_status, changed_at
FROM incident_history WHERE incident_id = 7 ORDER BY changed_at;

SELECT '   (b) Analyst moves it Open -> Investigating -> Resolved ...' AS `STEP`;
UPDATE incident SET status = 'Investigating' WHERE incident_id = 7;
UPDATE incident SET status = 'Resolved'      WHERE incident_id = 7;

SELECT '   (c) AFTER: status + resolved_at updated, and history auto-logged:' AS `STEP`;
SELECT incident_id, title, status, resolved_at FROM incident WHERE incident_id = 7;
SELECT history_id, action, old_status, new_status, changed_by, changed_at
FROM incident_history WHERE incident_id = 7 ORDER BY changed_at;

SELECT '>>> Two STATUS_CHANGE rows appeared with NO manual insert. <<<' AS `RESULT`;

-- -----------------------------------------------------------------------------
SELECT '7. CONSTRAINT DEMO (optional, read the note)' AS `STEP`;
SELECT 'Run this by hand to show a CHECK rejecting bad data:' AS `TRY`;
SELECT "  UPDATE incident SET status='Archived' WHERE incident_id=1;" AS `TRY`;
SELECT '  -> ERROR 3819: Check constraint chk_incident_status violated' AS `TRY`;

SELECT '========================  END OF DEMO  =======================' AS ``;
