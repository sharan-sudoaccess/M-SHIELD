-- =============================================================================
-- M-SHIELD : 07_advanced.sql
-- Purpose: Advanced database operations — stored function, stored procedures,
--          explicit cursor, transactions with SAVEPOINT, set operations, and
--          the remaining join types (RIGHT, CROSS, SELF).
-- DBMS CONCEPTS: CREATE FUNCTION / PROCEDURE, IN/OUT parameters, SIGNAL,
--                EXIT/CONTINUE handlers, CURSOR loop, START TRANSACTION,
--                SAVEPOINT, ROLLBACK TO, UNION / INTERSECT / EXCEPT (8.0.31+).
-- Run AFTER 01 -> 04 are loaded.
-- =============================================================================

USE mshield;

DROP FUNCTION  IF EXISTS fn_app_risk_score;
DROP FUNCTION  IF EXISTS fn_risk_band;
DROP PROCEDURE IF EXISTS sp_raise_incident;
DROP PROCEDURE IF EXISTS sp_auto_assign_incidents;

DELIMITER $$

-- -----------------------------------------------------------------------------
-- FUNCTION 1: numeric risk score for one application.
-- Permission weight (High 3, Medium 2, Low 1) + vulnerability weight
-- (Critical 10, High 6, Medium 3, Low 1). READS SQL DATA, returns a scalar.
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_app_risk_score(p_app_id INT)
RETURNS INT
READS SQL DATA
BEGIN
    DECLARE v_perm_score INT DEFAULT 0;
    DECLARE v_vuln_score INT DEFAULT 0;

    SELECT COALESCE(SUM(CASE p.risk_level WHEN 'High' THEN 3
                                          WHEN 'Medium' THEN 2 ELSE 1 END), 0)
      INTO v_perm_score
      FROM app_permission ap
      JOIN permission p ON p.permission_id = ap.permission_id
     WHERE ap.app_id = p_app_id;

    SELECT COALESCE(SUM(CASE severity WHEN 'Critical' THEN 10 WHEN 'High' THEN 6
                                      WHEN 'Medium' THEN 3 ELSE 1 END), 0)
      INTO v_vuln_score
      FROM vulnerability
     WHERE app_id = p_app_id;

    RETURN v_perm_score + v_vuln_score;
END$$

-- -----------------------------------------------------------------------------
-- FUNCTION 2: map a risk score to a band (pure function, no table access).
-- -----------------------------------------------------------------------------
CREATE FUNCTION fn_risk_band(p_score INT)
RETURNS VARCHAR(10)
DETERMINISTIC NO SQL
BEGIN
    RETURN CASE
        WHEN p_score >= 25 THEN 'Severe'
        WHEN p_score >= 12 THEN 'Elevated'
        ELSE 'Normal'
    END;
END$$

-- -----------------------------------------------------------------------------
-- PROCEDURE 1: raise a new incident for a vulnerability, atomically.
-- Validates the vulnerability, inserts the incident (the AFTER INSERT trigger
-- writes the CREATED audit row in the same transaction) and returns the new id
-- through an OUT parameter. Any error rolls the whole unit back and re-raises.
-- -----------------------------------------------------------------------------
CREATE PROCEDURE sp_raise_incident(
    IN  p_vuln_id     INT,
    IN  p_analyst_id  INT,
    IN  p_title       VARCHAR(150),
    IN  p_priority    VARCHAR(10),
    OUT p_incident_id INT)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    IF NOT EXISTS (SELECT 1 FROM vulnerability WHERE vuln_id = p_vuln_id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'sp_raise_incident: unknown vulnerability id';
    END IF;

    START TRANSACTION;
    INSERT INTO incident (vuln_id, assigned_analyst_id, title, priority)
    VALUES (p_vuln_id, p_analyst_id, p_title, p_priority);
    SET p_incident_id = LAST_INSERT_ID();
    COMMIT;
END$$

-- -----------------------------------------------------------------------------
-- PROCEDURE 2 (explicit CURSOR): auto-assign every unassigned, still-active
-- incident to the analyst with the fewest active incidents. Highest priority
-- and oldest incidents are served first. Returns the number assigned.
-- -----------------------------------------------------------------------------
CREATE PROCEDURE sp_auto_assign_incidents(OUT p_assigned INT)
BEGIN
    DECLARE v_done     INT DEFAULT 0;
    DECLARE v_incident INT;
    DECLARE v_analyst  INT;

    DECLARE cur_unassigned CURSOR FOR
        SELECT incident_id
          FROM incident
         WHERE assigned_analyst_id IS NULL
           AND status IN ('Open', 'Investigating')
         ORDER BY FIELD(priority, 'High', 'Medium', 'Low'), created_at;

    DECLARE CONTINUE HANDLER FOR NOT FOUND SET v_done = 1;

    SET p_assigned = 0;
    OPEN cur_unassigned;

    assign_loop: LOOP
        FETCH cur_unassigned INTO v_incident;
        IF v_done = 1 THEN
            LEAVE assign_loop;
        END IF;

        SET v_analyst = NULL;
        SELECT an.analyst_id INTO v_analyst
          FROM analyst an
          LEFT JOIN incident i
                 ON i.assigned_analyst_id = an.analyst_id
                AND i.status IN ('Open', 'Investigating')
         GROUP BY an.analyst_id
         ORDER BY COUNT(i.incident_id), an.analyst_id
         LIMIT 1;

        IF v_analyst IS NULL THEN          -- no analysts on file: stop
            LEAVE assign_loop;
        END IF;

        UPDATE incident SET assigned_analyst_id = v_analyst
         WHERE incident_id = v_incident;
        SET p_assigned = p_assigned + 1;
    END LOOP;

    CLOSE cur_unassigned;
END$$

DELIMITER ;

-- =============================================================================
-- DEMONSTRATIONS
-- =============================================================================

-- A1. Function in a query: risk score and band for every application.
SELECT a.app_name,
       fn_app_risk_score(a.app_id)               AS risk_score,
       fn_risk_band(fn_app_risk_score(a.app_id)) AS risk_band
FROM application a
ORDER BY risk_score DESC;

-- A2. Procedure with OUT parameter (trigger logs the CREATED row automatically).
CALL sp_raise_incident(3, 2, 'TorrentGo traffic re-test after patch', 'Medium', @new_id);
SELECT @new_id AS new_incident_id;
SELECT action, old_status, new_status FROM incident_history WHERE incident_id = @new_id;

-- A3. Procedure validation: an unknown vulnerability is rejected with SIGNAL.
--     (Uncomment to see: ERROR 1644 (45000): sp_raise_incident: unknown vulnerability id)
-- CALL sp_raise_incident(999, 1, 'Bogus', 'Low', @bad_id);

-- A4. Cursor procedure: assign every unassigned active incident.
CALL sp_auto_assign_incidents(@n);
SELECT @n AS incidents_assigned;
SELECT * FROM v_analyst_workload ORDER BY analyst_id;

-- A5. Transaction with SAVEPOINT and partial rollback (nothing is kept).
START TRANSACTION;
    UPDATE incident SET priority = 'High' WHERE incident_id = 3;
    SAVEPOINT after_priority;
    UPDATE incident SET status = 'Closed' WHERE incident_id = 3;
    SELECT incident_id, status, priority, resolved_at FROM incident WHERE incident_id = 3;
    ROLLBACK TO SAVEPOINT after_priority;   -- undo only the status change
    SELECT incident_id, status, priority, resolved_at FROM incident WHERE incident_id = 3;
ROLLBACK;                                   -- undo the priority change too
SELECT incident_id, status, priority FROM incident WHERE incident_id = 3;

-- -----------------------------------------------------------------------------
-- SET OPERATIONS (INTERSECT / EXCEPT need MySQL 8.0.31+)
-- -----------------------------------------------------------------------------
-- S1. UNION: every app that is a concern for EITHER reason.
SELECT a.app_name, 'high-risk permission' AS reason
FROM application a JOIN app_permission ap ON ap.app_id = a.app_id
JOIN permission p ON p.permission_id = ap.permission_id AND p.risk_level = 'High'
UNION
SELECT a.app_name, 'known vulnerability'
FROM application a JOIN vulnerability v ON v.app_id = a.app_id
ORDER BY app_name, reason;

-- S2. INTERSECT: apps that have BOTH a High-risk permission AND a vulnerability.
SELECT a.app_name FROM application a
JOIN app_permission ap ON ap.app_id = a.app_id
JOIN permission p ON p.permission_id = ap.permission_id AND p.risk_level = 'High'
INTERSECT
SELECT a.app_name FROM application a JOIN vulnerability v ON v.app_id = a.app_id
ORDER BY app_name;

-- S3. EXCEPT: apps with NO recorded vulnerability.
SELECT app_name FROM application
EXCEPT
SELECT a.app_name FROM application a JOIN vulnerability v ON v.app_id = a.app_id
ORDER BY app_name;

-- -----------------------------------------------------------------------------
-- REMAINING JOIN TYPES
-- -----------------------------------------------------------------------------
-- J1. RIGHT JOIN: how many apps request each permission (unused ones show 0).
SELECT p.name, p.risk_level, COUNT(ap.app_id) AS apps_requesting
FROM app_permission ap
RIGHT JOIN permission p ON p.permission_id = ap.permission_id
GROUP BY p.permission_id, p.name, p.risk_level
ORDER BY apps_requesting DESC, p.name;

-- J2. CROSS JOIN: device x severity matrix (every pair, even with zero vulns).
SELECT d.name AS device, s.severity, COUNT(v.vuln_id) AS vulns
FROM device d
CROSS JOIN (SELECT 'Critical' AS severity UNION ALL SELECT 'High'
            UNION ALL SELECT 'Medium' UNION ALL SELECT 'Low') s
LEFT JOIN application a   ON a.device_id = d.device_id
LEFT JOIN vulnerability v ON v.app_id = a.app_id AND v.severity = s.severity
GROUP BY d.device_id, d.name, s.severity
ORDER BY d.device_id, FIELD(s.severity, 'Critical', 'High', 'Medium', 'Low');

-- J3. SELF JOIN: pairs of apps on the same device that share a High-risk permission.
SELECT d.name AS device, a1.app_name AS app_1, a2.app_name AS app_2, p.name AS shared_permission
FROM app_permission ap1
JOIN app_permission ap2 ON ap2.permission_id = ap1.permission_id AND ap2.app_id > ap1.app_id
JOIN application a1 ON a1.app_id = ap1.app_id
JOIN application a2 ON a2.app_id = ap2.app_id AND a2.device_id = a1.device_id
JOIN device d       ON d.device_id = a1.device_id
JOIN permission p   ON p.permission_id = ap1.permission_id AND p.risk_level = 'High'
ORDER BY d.name, app_1, app_2;

-- End of 07_advanced.sql
