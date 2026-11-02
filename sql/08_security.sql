-- =============================================================================
-- M-SHIELD : 08_security.sql
-- Purpose: Data Control Language — roles, least-privilege accounts, GRANT and
--          REVOKE. Needs an account with CREATE USER / CREATE ROLE privileges.
-- DBMS CONCEPTS: authentication (accounts), authorization (roles + grants),
--                least privilege, REVOKE, SHOW GRANTS.
-- Replace the placeholder passwords before running; never commit real ones.
-- =============================================================================

USE mshield;

DROP USER IF EXISTS 'ms_viewer'@'localhost', 'ms_analyst'@'localhost';
DROP ROLE IF EXISTS 'mshield_readonly', 'mshield_analyst';

-- Roles: a read-only reporting role and an analyst role that may work incidents.
CREATE ROLE 'mshield_readonly', 'mshield_analyst';

GRANT SELECT ON mshield.v_high_severity_open_incidents TO 'mshield_readonly';
GRANT SELECT ON mshield.v_incident_full_detail         TO 'mshield_readonly';
GRANT SELECT ON mshield.v_analyst_workload             TO 'mshield_readonly';
GRANT SELECT ON mshield.v_apps_with_risky_permissions  TO 'mshield_readonly';

GRANT SELECT ON mshield.*                              TO 'mshield_analyst';
GRANT INSERT, UPDATE ON mshield.incident               TO 'mshield_analyst';
GRANT EXECUTE ON PROCEDURE mshield.sp_raise_incident   TO 'mshield_analyst';

-- Accounts, each given exactly one role as its default.
CREATE USER 'ms_viewer'@'localhost'  IDENTIFIED BY '<viewer-password>';
CREATE USER 'ms_analyst'@'localhost' IDENTIFIED BY '<analyst-password>';
GRANT 'mshield_readonly' TO 'ms_viewer'@'localhost';
GRANT 'mshield_analyst'  TO 'ms_analyst'@'localhost';
SET DEFAULT ROLE ALL TO 'ms_viewer'@'localhost', 'ms_analyst'@'localhost';

SHOW GRANTS FOR 'ms_analyst'@'localhost' USING 'mshield_analyst';

-- REVOKE: analysts may no longer edit incidents directly — only via the procedure.
REVOKE UPDATE ON mshield.incident FROM 'mshield_analyst';
SHOW GRANTS FOR 'mshield_analyst';

-- Clean-up (uncomment to remove the demo accounts and roles):
-- DROP USER IF EXISTS 'ms_viewer'@'localhost', 'ms_analyst'@'localhost';
-- DROP ROLE IF EXISTS 'mshield_readonly', 'mshield_analyst';

-- End of 08_security.sql
