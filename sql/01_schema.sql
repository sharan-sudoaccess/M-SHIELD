-- =============================================================================
-- M-SHIELD : Mobile Security Incident & Vulnerability Management System
-- File   : 01_schema.sql
-- Purpose: Schema definition — tables, keys, constraints, referential actions.
-- Engine : MySQL 8.x (InnoDB, utf8mb4). CHECK constraints require 8.0.16+.
-- -----------------------------------------------------------------------------
-- DBMS CONCEPTS DEMONSTRATED IN THIS FILE
--   * Logical schema design normalized to 3NF
--   * PRIMARY KEY (surrogate + composite) and FOREIGN KEY constraints
--   * Referential actions: ON DELETE CASCADE / SET NULL, ON UPDATE CASCADE
--   * Domain integrity via CHECK (enum emulation), NOT NULL, UNIQUE, DEFAULT
--   * Indexing of foreign keys for join performance
-- =============================================================================

-- Create and select a dedicated schema so the project is self-contained.
CREATE DATABASE IF NOT EXISTS mshield
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

USE mshield;

-- Drop in dependency-safe order if re-running (full reset lives in 06_teardown.sql).
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

-- -----------------------------------------------------------------------------
-- DEVICE  — the physical/virtual mobile endpoints under management.
-- Top of the ownership chain: deleting a device cascades to its applications.
-- -----------------------------------------------------------------------------
CREATE TABLE device (
    device_id   INT          NOT NULL AUTO_INCREMENT,
    name        VARCHAR(100) NOT NULL,
    os_type     VARCHAR(20)  NOT NULL,
    os_version  VARCHAR(20)  NOT NULL,
    owner_name  VARCHAR(100) NOT NULL,
    status      VARCHAR(20)  NOT NULL DEFAULT 'Active',
    CONSTRAINT pk_device PRIMARY KEY (device_id),
    -- Domain integrity: OS type and lifecycle status restricted to known values.
    CONSTRAINT chk_device_os
        CHECK (os_type IN ('Android', 'iOS')),
    CONSTRAINT chk_device_status
        CHECK (status IN ('Active', 'Quarantined', 'Retired'))
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- APPLICATION — apps installed on a device (DEVICE 1 : N APPLICATION).
-- FK device_id CASCADEs on delete so a device removal cleans up its apps.
-- -----------------------------------------------------------------------------
CREATE TABLE application (
    app_id       INT          NOT NULL AUTO_INCREMENT,
    device_id    INT          NOT NULL,
    app_name     VARCHAR(100) NOT NULL,
    version      VARCHAR(30)  NOT NULL,
    publisher    VARCHAR(100) NOT NULL,
    install_date DATE         NOT NULL,
    CONSTRAINT pk_application PRIMARY KEY (app_id),
    CONSTRAINT fk_application_device
        FOREIGN KEY (device_id) REFERENCES device (device_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;

-- Index the FK column to speed up device -> application joins and lookups.
CREATE INDEX idx_application_device ON application (device_id);

-- -----------------------------------------------------------------------------
-- PERMISSION — master list of Android/iOS permissions (reference / lookup table).
-- Keeping this separate (instead of storing permission strings on each app)
-- removes repeating groups and transitive dependency -> supports 3NF.
-- -----------------------------------------------------------------------------
CREATE TABLE permission (
    permission_id INT          NOT NULL AUTO_INCREMENT,
    name          VARCHAR(60)  NOT NULL,
    risk_level    VARCHAR(10)  NOT NULL,
    CONSTRAINT pk_permission PRIMARY KEY (permission_id),
    -- UNIQUE: a permission name is a natural key; never duplicated.
    CONSTRAINT uq_permission_name UNIQUE (name),
    CONSTRAINT chk_permission_risk
        CHECK (risk_level IN ('Low', 'Medium', 'High'))
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- APP_PERMISSION — associative (bridge) entity resolving the
-- APPLICATION M : N PERMISSION relationship. Composite PK prevents an app
-- from declaring the same permission twice.
-- -----------------------------------------------------------------------------
CREATE TABLE app_permission (
    app_id        INT NOT NULL,
    permission_id INT NOT NULL,
    CONSTRAINT pk_app_permission PRIMARY KEY (app_id, permission_id),
    CONSTRAINT fk_ap_application
        FOREIGN KEY (app_id) REFERENCES application (app_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    CONSTRAINT fk_ap_permission
        FOREIGN KEY (permission_id) REFERENCES permission (permission_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;

-- Secondary index on permission_id so "which apps use permission X" stays fast
-- (the composite PK already covers app_id-first lookups).
CREATE INDEX idx_ap_permission ON app_permission (permission_id);

-- -----------------------------------------------------------------------------
-- VULNERABILITY — a flaw discovered in an application (APPLICATION 1 : N VULN).
-- -----------------------------------------------------------------------------
CREATE TABLE vulnerability (
    vuln_id         INT          NOT NULL AUTO_INCREMENT,
    app_id          INT          NOT NULL,
    title           VARCHAR(150) NOT NULL,
    description     TEXT         NULL,
    severity        VARCHAR(10)  NOT NULL,
    cve_ref         VARCHAR(30)  NULL,
    discovered_date DATE         NOT NULL,
    CONSTRAINT pk_vulnerability PRIMARY KEY (vuln_id),
    CONSTRAINT fk_vulnerability_app
        FOREIGN KEY (app_id) REFERENCES application (app_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    CONSTRAINT chk_vuln_severity
        CHECK (severity IN ('Low', 'Medium', 'High', 'Critical'))
) ENGINE = InnoDB;

CREATE INDEX idx_vulnerability_app ON vulnerability (app_id);

-- -----------------------------------------------------------------------------
-- ANALYST — security staff who own incidents (ANALYST 1 : N INCIDENT).
-- -----------------------------------------------------------------------------
CREATE TABLE analyst (
    analyst_id INT          NOT NULL AUTO_INCREMENT,
    name       VARCHAR(100) NOT NULL,
    email      VARCHAR(150) NOT NULL,
    role       VARCHAR(50)  NOT NULL,
    CONSTRAINT pk_analyst PRIMARY KEY (analyst_id),
    CONSTRAINT uq_analyst_email UNIQUE (email)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- INCIDENT — a tracked case raised from a vulnerability.
--   * vuln_id            : NOT NULL  (an incident always stems from a vuln)
--   * assigned_analyst_id: NULLABLE  (an incident may be unassigned / triage)
-- Deleting the owning analyst SETs the FK to NULL so the incident record and
-- its audit trail survive (non-cascading on purpose).
-- -----------------------------------------------------------------------------
CREATE TABLE incident (
    incident_id         INT          NOT NULL AUTO_INCREMENT,
    vuln_id             INT          NOT NULL,
    assigned_analyst_id INT          NULL,
    title               VARCHAR(150) NOT NULL,
    status              VARCHAR(15)  NOT NULL DEFAULT 'Open',
    priority            VARCHAR(10)  NOT NULL DEFAULT 'Medium',
    created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at         DATETIME     NULL,
    CONSTRAINT pk_incident PRIMARY KEY (incident_id),
    CONSTRAINT fk_incident_vuln
        FOREIGN KEY (vuln_id) REFERENCES vulnerability (vuln_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    CONSTRAINT fk_incident_analyst
        FOREIGN KEY (assigned_analyst_id) REFERENCES analyst (analyst_id)
        ON DELETE SET NULL
        ON UPDATE CASCADE,
    CONSTRAINT chk_incident_status
        CHECK (status IN ('Open', 'Investigating', 'Resolved', 'Closed')),
    CONSTRAINT chk_incident_priority
        CHECK (priority IN ('Low', 'Medium', 'High')),
    -- A resolved/closed incident must not pre-date its own creation.
    CONSTRAINT chk_incident_resolved_order
        CHECK (resolved_at IS NULL OR resolved_at >= created_at)
) ENGINE = InnoDB;

CREATE INDEX idx_incident_vuln    ON incident (vuln_id);
CREATE INDEX idx_incident_analyst ON incident (assigned_analyst_id);
CREATE INDEX idx_incident_status  ON incident (status);

-- -----------------------------------------------------------------------------
-- INCIDENT_HISTORY — append-only audit log (INCIDENT 1 : N HISTORY).
-- Rows are written automatically by triggers (see 04_triggers.sql) whenever an
-- incident is created or its status changes. Separating this volatile audit
-- data from the INCIDENT entity avoids update anomalies and keeps 3NF.
-- -----------------------------------------------------------------------------
CREATE TABLE incident_history (
    history_id  INT          NOT NULL AUTO_INCREMENT,
    incident_id INT          NOT NULL,
    action      VARCHAR(40)  NOT NULL,
    old_status  VARCHAR(15)  NULL,
    new_status  VARCHAR(15)  NULL,
    changed_by  VARCHAR(100) NOT NULL,
    changed_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_incident_history PRIMARY KEY (history_id),
    CONSTRAINT fk_history_incident
        FOREIGN KEY (incident_id) REFERENCES incident (incident_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE = InnoDB;

CREATE INDEX idx_history_incident ON incident_history (incident_id);

-- End of 01_schema.sql
