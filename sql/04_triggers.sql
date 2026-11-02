-- =============================================================================
-- M-SHIELD : 04_triggers.sql
-- Purpose: Triggers that automate the INCIDENT_HISTORY audit trail and keep
--          resolved_at consistent with status.
-- DBMS CONCEPTS: AFTER INSERT / AFTER UPDATE / BEFORE UPDATE triggers,
--                OLD vs NEW row references, procedural SQL, DELIMITER handling.
-- Run this AFTER sample data is loaded; the triggers fire on future DML only.
-- =============================================================================

USE mshield;

DROP TRIGGER IF EXISTS trg_incident_after_insert;
DROP TRIGGER IF EXISTS trg_incident_before_update;
DROP TRIGGER IF EXISTS trg_incident_after_update;

DELIMITER $$

-- -----------------------------------------------------------------------------
-- TRIGGER 1 (AFTER INSERT): log the creation of every new incident.
-- Writes a 'CREATED' audit row capturing the initial status.
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_incident_after_insert
AFTER INSERT ON incident
FOR EACH ROW
BEGIN
    INSERT INTO incident_history
        (incident_id, action, old_status, new_status, changed_by, changed_at)
    VALUES
        (NEW.incident_id, 'CREATED', NULL, NEW.status, CURRENT_USER(), NOW());
END$$

-- -----------------------------------------------------------------------------
-- TRIGGER 2 (BEFORE UPDATE): keep resolved_at in sync with status.
-- Moving into Resolved/Closed stamps resolved_at (if not already set);
-- reopening clears it. Runs BEFORE so it can modify NEW.* in place.
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_incident_before_update
BEFORE UPDATE ON incident
FOR EACH ROW
BEGIN
    IF NEW.status <> OLD.status THEN
        IF NEW.status IN ('Resolved', 'Closed') AND NEW.resolved_at IS NULL THEN
            SET NEW.resolved_at = NOW();
        ELSEIF NEW.status IN ('Open', 'Investigating') THEN
            SET NEW.resolved_at = NULL;
        END IF;
    END IF;
END$$

-- -----------------------------------------------------------------------------
-- TRIGGER 3 (AFTER UPDATE): the core requirement — auto-log any status change
-- into INCIDENT_HISTORY. Only writes when status actually differs, so routine
-- edits (e.g. retitling) don't pollute the audit trail.
-- -----------------------------------------------------------------------------
CREATE TRIGGER trg_incident_after_update
AFTER UPDATE ON incident
FOR EACH ROW
BEGIN
    IF NEW.status <> OLD.status THEN
        INSERT INTO incident_history
            (incident_id, action, old_status, new_status, changed_by, changed_at)
        VALUES
            (NEW.incident_id, 'STATUS_CHANGE', OLD.status, NEW.status,
             CURRENT_USER(), NOW());
    END IF;
END$$

DELIMITER ;

-- End of 04_triggers.sql
