-- =============================================================================
-- M-SHIELD : 06_teardown.sql
-- Purpose: Clean reset — drop every object this project creates.
-- DBMS CONCEPTS: dependency-aware DROP ordering, idempotent teardown.
-- Safe to run repeatedly; IF EXISTS guards avoid errors on a fresh DB.
-- =============================================================================

USE mshield;

-- Triggers first (they depend on the incident table).
DROP TRIGGER IF EXISTS trg_incident_after_insert;
DROP TRIGGER IF EXISTS trg_incident_before_update;
DROP TRIGGER IF EXISTS trg_incident_after_update;

-- Stored routines from 07_advanced.sql.
DROP PROCEDURE IF EXISTS sp_raise_incident;
DROP PROCEDURE IF EXISTS sp_auto_assign_incidents;
DROP FUNCTION  IF EXISTS fn_app_risk_score;
DROP FUNCTION  IF EXISTS fn_risk_band;

-- Views (depend on base tables).
DROP VIEW IF EXISTS v_high_severity_open_incidents;
DROP VIEW IF EXISTS v_apps_with_risky_permissions;
DROP VIEW IF EXISTS v_incident_full_detail;
DROP VIEW IF EXISTS v_analyst_workload;

-- Tables, child-to-parent (FK checks off as a belt-and-braces safeguard).
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS incident_history;
DROP TABLE IF EXISTS incident;
DROP TABLE IF EXISTS analyst;
DROP TABLE IF EXISTS vulnerability;
DROP TABLE IF EXISTS app_permission;
DROP TABLE IF EXISTS permission;
DROP TABLE IF EXISTS application;
DROP TABLE IF EXISTS device;
SET FOREIGN_KEY_CHECKS = 1;

-- Optionally remove the schema entirely (uncomment to drop the database):
-- DROP DATABASE IF EXISTS mshield;

-- End of 06_teardown.sql
