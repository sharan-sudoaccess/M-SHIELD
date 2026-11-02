-- =============================================================================
-- M-SHIELD : 03_views.sql
-- Purpose: Reporting VIEWS — reusable, join-backed virtual tables.
-- DBMS CONCEPTS: VIEW definition, multi-table JOINs behind a view, derived
--                columns, aggregation inside a view, and query simplification.
-- =============================================================================

USE mshield;

DROP VIEW IF EXISTS v_high_severity_open_incidents;
DROP VIEW IF EXISTS v_apps_with_risky_permissions;
DROP VIEW IF EXISTS v_incident_full_detail;
DROP VIEW IF EXISTS v_analyst_workload;

-- -----------------------------------------------------------------------------
-- VIEW 1: High-severity, still-active incidents.
-- Combines the incident with its originating vulnerability, the affected app,
-- its device, and the owning analyst. "Active" = not Resolved/Closed.
-- -----------------------------------------------------------------------------
CREATE VIEW v_high_severity_open_incidents AS
SELECT
    i.incident_id,
    i.title                         AS incident_title,
    i.status,
    i.priority,
    v.severity                      AS vuln_severity,
    v.title                         AS vuln_title,
    a.app_name,
    d.name                          AS device_name,
    d.owner_name,
    COALESCE(an.name, '(unassigned)') AS analyst,
    i.created_at
FROM incident        i
JOIN vulnerability   v  ON v.vuln_id   = i.vuln_id
JOIN application     a  ON a.app_id    = v.app_id
JOIN device          d  ON d.device_id = a.device_id
LEFT JOIN analyst    an ON an.analyst_id = i.assigned_analyst_id
WHERE v.severity IN ('High', 'Critical')
  AND i.status   IN ('Open', 'Investigating');

-- -----------------------------------------------------------------------------
-- VIEW 2: Apps that hold one or more High-risk permissions, with a rolled-up
-- list of exactly which risky permissions they requested.
-- GROUP_CONCAT turns the M:N rows into a readable summary per app.
-- -----------------------------------------------------------------------------
CREATE VIEW v_apps_with_risky_permissions AS
SELECT
    a.app_id,
    a.app_name,
    a.publisher,
    d.name                               AS device_name,
    COUNT(*)                             AS risky_permission_count,
    GROUP_CONCAT(p.name ORDER BY p.name SEPARATOR ', ') AS risky_permissions
FROM application    a
JOIN device         d ON d.device_id = a.device_id
JOIN app_permission ap ON ap.app_id   = a.app_id
JOIN permission     p ON p.permission_id = ap.permission_id
WHERE p.risk_level = 'High'
GROUP BY a.app_id, a.app_name, a.publisher, d.name;

-- -----------------------------------------------------------------------------
-- VIEW 3: Fully denormalized incident report (device -> app -> vuln ->
-- incident -> analyst). Handy single object for dashboards and ad-hoc filters.
-- -----------------------------------------------------------------------------
CREATE VIEW v_incident_full_detail AS
SELECT
    i.incident_id,
    i.title                 AS incident_title,
    i.status,
    i.priority,
    i.created_at,
    i.resolved_at,
    v.vuln_id,
    v.title                 AS vuln_title,
    v.severity,
    v.cve_ref,
    a.app_id,
    a.app_name,
    a.publisher,
    d.device_id,
    d.name                  AS device_name,
    d.os_type,
    d.owner_name,
    an.analyst_id,
    an.name                 AS analyst_name,
    an.role                 AS analyst_role
FROM incident        i
JOIN vulnerability   v  ON v.vuln_id    = i.vuln_id
JOIN application     a  ON a.app_id     = v.app_id
JOIN device          d  ON d.device_id  = a.device_id
LEFT JOIN analyst    an ON an.analyst_id = i.assigned_analyst_id;

-- -----------------------------------------------------------------------------
-- VIEW 4: Analyst workload summary — total vs. still-open incidents.
-- Aggregation + conditional counting behind a view.
-- -----------------------------------------------------------------------------
CREATE VIEW v_analyst_workload AS
SELECT
    an.analyst_id,
    an.name,
    an.role,
    COUNT(i.incident_id)                                              AS total_incidents,
    SUM(CASE WHEN i.status IN ('Open','Investigating') THEN 1 ELSE 0 END) AS open_incidents,
    SUM(CASE WHEN i.status IN ('Resolved','Closed')    THEN 1 ELSE 0 END) AS closed_incidents
FROM analyst   an
LEFT JOIN incident i ON i.assigned_analyst_id = an.analyst_id
GROUP BY an.analyst_id, an.name, an.role;

-- Quick smoke test (optional): uncomment to eyeball the views after creation.
-- SELECT * FROM v_high_severity_open_incidents;
-- SELECT * FROM v_apps_with_risky_permissions;
-- SELECT * FROM v_analyst_workload;

-- End of 03_views.sql
