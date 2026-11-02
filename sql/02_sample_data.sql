-- =============================================================================
-- M-SHIELD : 02_sample_data.sql
-- Purpose: Realistic but clearly SIMULATED sample data.
-- Notes  : Loaded BEFORE triggers (04) are created, so the history rows here
--          are inserted manually to represent past activity. Later, in
--          05_queries.sql, an UPDATE demonstrates the trigger writing history
--          automatically. All security data is fictional / for teaching only.
-- DBMS CONCEPTS: INSERT with explicit column lists, use of DEFAULTs, multi-row
--                VALUES, and populating an associative table for an M:N relation.
-- =============================================================================

USE mshield;

-- Make the load idempotent: clear existing rows in child-to-parent order so it
-- re-runs cleanly even without re-running 01. DELETE (not TRUNCATE) is used
-- because TRUNCATE on FK-referenced tables is restricted; explicit id values in
-- the INSERTs below mean AUTO_INCREMENT need not be reset here (done at the end).
DELETE FROM incident_history;
DELETE FROM incident;
DELETE FROM vulnerability;
DELETE FROM app_permission;
DELETE FROM application;
DELETE FROM analyst;
DELETE FROM permission;
DELETE FROM device;

-- -----------------------------------------------------------------------------
-- DEVICE (5 rows) — mix of Android/iOS and lifecycle states.
-- -----------------------------------------------------------------------------
INSERT INTO device (device_id, name, os_type, os_version, owner_name, status) VALUES
    (1, 'Pixel 7',    'Android', '14',   'Alice Johnson', 'Active'),
    (2, 'iPhone 14',  'iOS',     '17.2', 'Bob Smith',     'Active'),
    (3, 'Galaxy S22', 'Android', '13',   'Carol Lee',     'Quarantined'),
    (4, 'OnePlus 11', 'Android', '14',   'David Kim',     'Active'),
    (5, 'iPhone SE',  'iOS',     '16.5', 'Emma Davis',    'Retired');

-- -----------------------------------------------------------------------------
-- APPLICATION (10 rows) — at least one deliberately shady app per the brief.
-- -----------------------------------------------------------------------------
INSERT INTO application (app_id, device_id, app_name, version, publisher, install_date) VALUES
    (1,  1, 'WhatsApp',        '2.24.3',  'Meta Platforms', '2024-01-12'),
    (2,  1, 'FreeFlashlight',  '1.2',     'BrightApps Inc', '2024-03-02'),
    (3,  2, 'Instagram',       '312.0',   'Meta Platforms', '2024-02-20'),
    (4,  2, 'BankSecure',      '5.1.0',   'FinCorp',        '2023-11-05'),
    (5,  3, 'QuickCleaner',    '3.0',     'Shady Labs',     '2024-04-18'),
    (6,  3, 'Gmail',           '2024.04', 'Google LLC',     '2023-09-30'),
    (7,  4, 'Spotify',         '8.9',     'Spotify AB',     '2024-01-25'),
    (8,  4, 'TorrentGo',       '2.2',     'P2P Devs',       '2024-05-01'),
    (9,  5, 'Safari',          '16.5',    'Apple Inc',      '2023-06-15'),
    (10, 1, 'GameHub',         '4.5',     'FunZone',        '2024-03-19');

-- -----------------------------------------------------------------------------
-- PERMISSION (12 rows) — master list with assigned risk weighting.
-- -----------------------------------------------------------------------------
INSERT INTO permission (permission_id, name, risk_level) VALUES
    (1,  'CAMERA',         'High'),
    (2,  'MICROPHONE',     'High'),
    (3,  'LOCATION_FINE',  'High'),
    (4,  'LOCATION_COARSE','Medium'),
    (5,  'READ_CONTACTS',  'High'),
    (6,  'READ_SMS',       'High'),
    (7,  'SEND_SMS',       'High'),
    (8,  'READ_STORAGE',   'Medium'),
    (9,  'WRITE_STORAGE',  'Medium'),
    (10, 'READ_CALL_LOG',  'High'),
    (11, 'INTERNET',       'Low'),
    (12, 'BLUETOOTH',      'Low');

-- -----------------------------------------------------------------------------
-- APP_PERMISSION (M:N) — note QuickCleaner (app 5) hoards SMS + Contacts +
-- Location + Call log: the classic "flashlight asks for everything" pattern.
-- -----------------------------------------------------------------------------
INSERT INTO app_permission (app_id, permission_id) VALUES
    -- WhatsApp: camera, mic, contacts, storage, internet (expected for a messenger)
    (1, 1), (1, 2), (1, 5), (1, 8), (1, 11),
    -- FreeFlashlight: should need nothing — asks for camera + location + contacts (suspicious)
    (2, 1), (2, 3), (2, 5), (2, 11),
    -- Instagram: camera, mic, location, storage, internet
    (3, 1), (3, 2), (3, 4), (3, 8), (3, 11),
    -- BankSecure: minimal + internet (well-behaved banking app)
    (4, 8), (4, 11),
    -- QuickCleaner: SMS read+send, contacts, call log, fine location, storage, internet (High risk)
    (5, 5), (5, 6), (5, 7), (5, 10), (5, 3), (5, 9), (5, 11),
    -- Gmail: contacts, storage, internet
    (6, 5), (6, 8), (6, 11),
    -- Spotify: mic, storage, bluetooth, internet
    (7, 2), (7, 9), (7, 12), (7, 11),
    -- TorrentGo: storage read+write, internet
    (8, 8), (8, 9), (8, 11),
    -- Safari: location coarse, internet
    (9, 4), (9, 11),
    -- GameHub: storage, internet, bluetooth
    (10, 8), (10, 11), (10, 12);

-- -----------------------------------------------------------------------------
-- VULNERABILITY (8 rows) — tied to the apps above.
-- -----------------------------------------------------------------------------
INSERT INTO vulnerability
    (vuln_id, app_id, title, description, severity, cve_ref, discovered_date) VALUES
    (1, 5, 'SMS exfiltration via excessive permissions',
        'QuickCleaner reads and forwards SMS messages to an external endpoint.',
        'Critical', 'CVE-2024-11001', '2024-05-10'),
    (2, 2, 'Unnecessary background location tracking',
        'FreeFlashlight collects fine location with no functional need.',
        'High', NULL, '2024-04-22'),
    (3, 8, 'Cleartext data transmission',
        'TorrentGo transfers user data over unencrypted HTTP.',
        'High', 'CVE-2024-11042', '2024-05-14'),
    (4, 4, 'Hardcoded API credentials',
        'BankSecure ships a static API key in the APK, extractable via decompile.',
        'Critical', 'CVE-2023-98877', '2024-02-01'),
    (5, 3, 'Outdated TLS library',
        'Instagram build links a TLS library with known downgrade weaknesses.',
        'Medium', 'CVE-2024-10233', '2024-03-08'),
    (6, 1, 'Unencrypted local backup',
        'WhatsApp chat backup stored on shared storage without encryption.',
        'Medium', NULL, '2024-03-15'),
    (7, 10, 'Over-privileged storage access',
        'GameHub requests broad storage access beyond its save-file needs.',
        'Low', NULL, '2024-04-02'),
    (8, 5, 'Hidden background data collection',
        'QuickCleaner harvests contacts and call logs silently on launch.',
        'High', 'CVE-2024-11005', '2024-05-12');

-- -----------------------------------------------------------------------------
-- ANALYST (4 rows).
-- -----------------------------------------------------------------------------
INSERT INTO analyst (analyst_id, name, email, role) VALUES
    (1, 'Priya Nair',   'priya.nair@mshield.io',   'Lead Analyst'),
    (2, 'Marcus Chen',  'marcus.chen@mshield.io',  'Security Analyst'),
    (3, 'Sofia Rossi',  'sofia.rossi@mshield.io',  'Junior Analyst'),
    (4, 'Tom Baker',    'tom.baker@mshield.io',    'Incident Manager');

-- -----------------------------------------------------------------------------
-- INCIDENT (8 rows) — incident 8 is intentionally UNASSIGNED (NULL analyst)
-- to exercise ON DELETE SET NULL and LEFT JOIN scenarios.
-- -----------------------------------------------------------------------------
INSERT INTO incident
    (incident_id, vuln_id, assigned_analyst_id, title, status, priority, created_at, resolved_at) VALUES
    (1, 1, 1, 'Investigate QuickCleaner SMS exfiltration', 'Investigating', 'High',   '2024-05-11 09:15:00', NULL),
    (2, 4, 1, 'Remediate BankSecure hardcoded key',        'Open',          'High',   '2024-02-02 10:00:00', NULL),
    (3, 3, 2, 'TorrentGo cleartext traffic review',        'Open',          'Medium', '2024-05-15 14:30:00', NULL),
    (4, 2, 3, 'FreeFlashlight location abuse',             'Resolved',      'Medium', '2024-04-23 08:45:00', '2024-04-29 16:20:00'),
    (5, 8, 2, 'QuickCleaner silent data harvesting',       'Investigating', 'High',   '2024-05-13 11:05:00', NULL),
    (6, 5, 3, 'Instagram TLS downgrade check',             'Closed',        'Low',    '2024-03-09 13:10:00', '2024-03-20 09:00:00'),
    (7, 6, 4, 'WhatsApp backup encryption follow-up',      'Open',          'Medium', '2024-03-16 15:40:00', NULL),
    (8, 7, NULL, 'GameHub storage permissions triage',     'Open',          'Low',    '2024-04-03 12:00:00', NULL);

-- -----------------------------------------------------------------------------
-- INCIDENT_HISTORY — manual seed of prior activity (pre-trigger history).
-- The 'CREATED' rows mirror what the AFTER INSERT trigger would have written;
-- subsequent rows show real status transitions for the two closed/resolved cases.
-- -----------------------------------------------------------------------------
INSERT INTO incident_history
    (incident_id, action, old_status, new_status, changed_by, changed_at) VALUES
    (1, 'CREATED',       NULL,           'Open',          'priya.nair@mshield.io',  '2024-05-11 09:15:00'),
    (1, 'STATUS_CHANGE', 'Open',         'Investigating', 'priya.nair@mshield.io',  '2024-05-11 10:02:00'),
    (4, 'CREATED',       NULL,           'Open',          'sofia.rossi@mshield.io', '2024-04-23 08:45:00'),
    (4, 'STATUS_CHANGE', 'Open',         'Investigating', 'sofia.rossi@mshield.io', '2024-04-24 09:30:00'),
    (4, 'STATUS_CHANGE', 'Investigating','Resolved',      'sofia.rossi@mshield.io', '2024-04-29 16:20:00'),
    (6, 'CREATED',       NULL,           'Open',          'sofia.rossi@mshield.io', '2024-03-09 13:10:00'),
    (6, 'STATUS_CHANGE', 'Open',         'Investigating', 'sofia.rossi@mshield.io', '2024-03-10 10:15:00'),
    (6, 'STATUS_CHANGE', 'Investigating','Resolved',      'sofia.rossi@mshield.io', '2024-03-18 14:00:00'),
    (6, 'STATUS_CHANGE', 'Resolved',     'Closed',        'tom.baker@mshield.io',   '2024-03-20 09:00:00');

-- Keep AUTO_INCREMENT counters above the highest seeded id so trigger/app
-- inserts continue cleanly.
ALTER TABLE device           AUTO_INCREMENT = 6;
ALTER TABLE application      AUTO_INCREMENT = 11;
ALTER TABLE permission       AUTO_INCREMENT = 13;
ALTER TABLE vulnerability    AUTO_INCREMENT = 9;
ALTER TABLE analyst          AUTO_INCREMENT = 5;
ALTER TABLE incident         AUTO_INCREMENT = 9;

-- End of 02_sample_data.sql
