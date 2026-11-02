-- =============================================================================
-- M-SHIELD : 05_queries.sql
-- Purpose: Demonstrative queries exercising the schema, views and trigger.
-- DBMS CONCEPTS: inner/outer joins, 3+ table join, aggregation, GROUP BY /
--                HAVING, subqueries, set operations, trigger verification.
-- Each query is numbered with the concept it illustrates.
-- =============================================================================

USE mshield;

-- -----------------------------------------------------------------------------
-- Q1. Basic lookup — every application with its host device (INNER JOIN, 2 tables).
-- -----------------------------------------------------------------------------
SELECT a.app_name, a.publisher, d.name AS device, d.os_type
FROM application a
JOIN device d ON d.device_id = a.device_id
ORDER BY d.name, a.app_name;

-- -----------------------------------------------------------------------------
-- Q2. JOIN-HEAVY query across 5 tables: device -> app -> vulnerability ->
-- incident -> analyst. The flagship multi-table join.
-- -----------------------------------------------------------------------------
SELECT
    d.name            AS device,
    a.app_name,
    v.title           AS vulnerability,
    v.severity,
    i.title           AS incident,
    i.status,
    COALESCE(an.name, '(unassigned)') AS analyst
FROM incident      i
JOIN vulnerability v  ON v.vuln_id    = i.vuln_id
JOIN application   a  ON a.app_id     = v.app_id
JOIN device        d  ON d.device_id  = a.device_id
LEFT JOIN analyst  an ON an.analyst_id = i.assigned_analyst_id
ORDER BY FIELD(v.severity,'Critical','High','Medium','Low'), d.name;

-- -----------------------------------------------------------------------------
-- Q3. Aggregation — vulnerability count per severity (GROUP BY).
-- -----------------------------------------------------------------------------
SELECT severity, COUNT(*) AS vuln_count
FROM vulnerability
GROUP BY severity
ORDER BY FIELD(severity,'Critical','High','Medium','Low');

-- -----------------------------------------------------------------------------
-- Q4. Aggregation — incident count per analyst, including analysts with none
-- (LEFT JOIN so zero-workload analysts still appear).
-- -----------------------------------------------------------------------------
SELECT an.name, an.role, COUNT(i.incident_id) AS incidents_handled
FROM analyst   an
LEFT JOIN incident i ON i.assigned_analyst_id = an.analyst_id
GROUP BY an.analyst_id, an.name, an.role
ORDER BY incidents_handled DESC, an.name;

-- -----------------------------------------------------------------------------
-- Q5. GROUP BY + HAVING — apps requesting 3 or more High-risk permissions.
-- -----------------------------------------------------------------------------
SELECT a.app_name, COUNT(*) AS high_risk_perms
FROM application    a
JOIN app_permission ap ON ap.app_id = a.app_id
JOIN permission     p  ON p.permission_id = ap.permission_id
WHERE p.risk_level = 'High'
GROUP BY a.app_id, a.app_name
HAVING COUNT(*) >= 3
ORDER BY high_risk_perms DESC;

-- -----------------------------------------------------------------------------
-- Q6. Correlated subquery — apps that have at least one Critical vulnerability.
-- -----------------------------------------------------------------------------
SELECT a.app_name, a.publisher
FROM application a
WHERE EXISTS (
    SELECT 1 FROM vulnerability v
    WHERE v.app_id = a.app_id AND v.severity = 'Critical'
);

-- -----------------------------------------------------------------------------
-- Q7. Scalar subquery in SELECT — each device with its installed-app count.
-- -----------------------------------------------------------------------------
SELECT
    d.name,
    d.status,
    (SELECT COUNT(*) FROM application a WHERE a.device_id = d.device_id) AS app_count
FROM device d
ORDER BY app_count DESC;

-- -----------------------------------------------------------------------------
-- Q8. Querying a VIEW — read the high-severity open incidents report directly.
-- -----------------------------------------------------------------------------
SELECT * FROM v_high_severity_open_incidents
ORDER BY FIELD(vuln_severity,'Critical','High'), created_at;

-- -----------------------------------------------------------------------------
-- Q9. Anti-join / NOT IN — vulnerabilities that have NOT yet become an incident.
-- -----------------------------------------------------------------------------
SELECT v.vuln_id, v.title, v.severity
FROM vulnerability v
WHERE v.vuln_id NOT IN (SELECT i.vuln_id FROM incident i)
ORDER BY v.severity;

-- -----------------------------------------------------------------------------
-- Q10. Average resolution time (hours) for closed/resolved incidents
-- (date arithmetic + aggregation).
-- -----------------------------------------------------------------------------
SELECT
    COUNT(*)                                             AS resolved_count,
    ROUND(AVG(TIMESTAMPDIFF(HOUR, created_at, resolved_at)), 1) AS avg_hours_to_resolve
FROM incident
WHERE resolved_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- Q11. Full audit trail for one incident, newest first (reads INCIDENT_HISTORY).
-- -----------------------------------------------------------------------------
SELECT incident_id, action, old_status, new_status, changed_by, changed_at
FROM incident_history
WHERE incident_id = 1
ORDER BY changed_at DESC;

-- =============================================================================
-- Q12. TRIGGER DEMONSTRATION
-- Change an incident's status and watch INCIDENT_HISTORY get a new row
-- automatically (trg_incident_after_update), with resolved_at auto-stamped
-- by trg_incident_before_update.
-- =============================================================================

-- Before:
SELECT incident_id, status, resolved_at FROM incident WHERE incident_id = 2;
SELECT COUNT(*) AS history_rows_before FROM incident_history WHERE incident_id = 2;

-- Fire the trigger: move incident 2 from Open -> Resolved.
UPDATE incident SET status = 'Resolved' WHERE incident_id = 2;

-- After: resolved_at is now populated and a STATUS_CHANGE row was logged.
SELECT incident_id, status, resolved_at FROM incident WHERE incident_id = 2;
SELECT action, old_status, new_status, changed_by, changed_at
FROM incident_history
WHERE incident_id = 2
ORDER BY changed_at;

-- End of 05_queries.sql
