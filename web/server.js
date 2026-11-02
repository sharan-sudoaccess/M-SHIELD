// =============================================================================
// M-SHIELD web backend  —  zero-dependency Node server with full CRUD.
// Talks to the LIVE MySQL `mshield` database through the installed `mysql`
// client (no npm packages). Serves a JSON API + the interactive dashboard.
//
// Run:  DB_PASS=MShield2026 node server.js      (then open http://localhost:3000)
// =============================================================================
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const PORT = process.env.PORT || 3000;
const DB_USER = process.env.DB_USER || 'mshield_demo';
const DB_PASS = process.env.DB_PASS || 'MShield2026';
const DB_NAME = process.env.DB_NAME || 'mshield';

const STATUSES = ['Open', 'Investigating', 'Resolved', 'Closed'];
const SEVERITIES = ['Low', 'Medium', 'High', 'Critical'];
const PRIORITIES = ['Low', 'Medium', 'High'];
const RISKS = ['Low', 'Medium', 'High'];
const OS_TYPES = ['Android', 'iOS'];
const DEV_STATUS = ['Active', 'Quarantined', 'Retired'];

// -----------------------------------------------------------------------------
// Run SQL through the mysql CLI (tab-separated --batch output -> objects).
// Password via MYSQL_PWD env, never on the command line.
// -----------------------------------------------------------------------------
function runQuery(sql) {
  return new Promise((resolve, reject) => {
    execFile(
      'mysql',
      ['-u', DB_USER, DB_NAME, '--batch', '--default-character-set=utf8mb4', '-e', sql],
      { env: { ...process.env, MYSQL_PWD: DB_PASS }, maxBuffer: 2 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) return reject(new Error(cleanErr(stderr || err.message)));
        const lines = stdout.replace(/\n$/, '').split('\n');
        if (!lines[0]) return resolve([]);
        const cols = lines[0].split('\t');
        resolve(lines.slice(1).map((line) => {
          const cells = line.split('\t');
          const o = {};
          cols.forEach((c, i) => {
            let v = cells[i] === undefined ? null : cells[i];
            if (v === 'NULL') v = null;
            else v = v.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\\\/g, '\\');
            o[c] = v;
          });
          return o;
        }));
      }
    );
  });
}

// Turn raw MySQL errors into something readable in a toast.
function cleanErr(msg) {
  msg = String(msg).replace(/^ERROR \d+ \([0-9A-Z]+\) at line \d+: /, '').trim();
  if (/Duplicate entry/.test(msg)) return 'That value must be unique — it already exists.';
  if (/foreign key constraint fails/i.test(msg)) return 'Blocked by a foreign-key constraint (referenced row missing or still in use).';
  if (/Check constraint/.test(msg)) return 'Rejected by a CHECK constraint (value not allowed).';
  if (/cannot be null/i.test(msg)) return 'A required (NOT NULL) field was empty.';
  return msg;
}

// ---- value sanitizers (the mysql CLI has no bind params) --------------------
const ESC = { '\\': '\\\\', '\0': '\\0', '\n': '\\n', '\r': '\\r',
              '\x08': '\\b', '\x09': '\\t', '\x1a': '\\Z', "'": "\\'", '"': '\\"' };
const str = (v) => "'" + String(v).replace(/[\\\0\n\r\x08\x09\x1a'"]/g, (c) => ESC[c]) + "'";
const need = (v, n) => { if (v === undefined || v === null || String(v).trim() === '') throw new Error(`${n} is required`); return v; };
const strReq = (v, n) => str(need(v, n));
const strOrNull = (v) => (v === undefined || v === null || String(v).trim() === '') ? 'NULL' : str(v);
const intReq = (v, n) => { const x = parseInt(v, 10); if (!Number.isInteger(x)) throw new Error(`${n} must be selected`); return x; };
const intOrNull = (v) => { if (v === undefined || v === null || v === '' || v === 'null') return 'NULL'; const x = parseInt(v, 10); if (!Number.isInteger(x)) throw new Error('invalid id'); return x; };
const oneOf = (v, allow, n) => { if (!allow.includes(v)) throw new Error(`${n} must be one of: ${allow.join(', ')}`); return str(v); };
const dateReq = (v, n) => { if (!/^\d{4}-\d{2}-\d{2}$/.test(v || '')) throw new Error(`${n} must be a date (YYYY-MM-DD)`); return str(v); };
const dateOrNull = (v) => { if (!v) return 'NULL'; if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) throw new Error('date must be YYYY-MM-DD'); return str(v); };

const INCIDENT_SELECT = `
  SELECT i.incident_id, i.title, i.status, i.priority,
         DATE_FORMAT(i.created_at,'%Y-%m-%d %H:%i')  AS created_at,
         DATE_FORMAT(i.resolved_at,'%Y-%m-%d %H:%i') AS resolved_at,
         i.vuln_id, i.assigned_analyst_id,
         v.severity, v.title AS vuln_title, v.cve_ref,
         a.app_name, d.name AS device_name, d.os_type,
         COALESCE(an.name,'(unassigned)') AS analyst
  FROM incident i
  JOIN vulnerability v ON v.vuln_id = i.vuln_id
  JOIN application   a ON a.app_id  = v.app_id
  JOIN device        d ON d.device_id = a.device_id
  LEFT JOIN analyst an ON an.analyst_id = i.assigned_analyst_id`;

// -----------------------------------------------------------------------------
// API handlers
// -----------------------------------------------------------------------------
const api = {
  // ---- dropdown option lists for forms ----
  async lists() {
    const devices = await runQuery(`SELECT device_id AS v, name AS t FROM device ORDER BY name`);
    const apps = await runQuery(`SELECT a.app_id AS v, CONCAT(a.app_name,' · ',d.name) AS t FROM application a JOIN device d ON d.device_id=a.device_id ORDER BY a.app_name`);
    const vulns = await runQuery(`SELECT v.vuln_id AS v, CONCAT(v.title,' (',v.severity,')') AS t FROM vulnerability v ORDER BY FIELD(v.severity,'Critical','High','Medium','Low'), v.title`);
    const analysts = await runQuery(`SELECT analyst_id AS v, name AS t FROM analyst ORDER BY name`);
    const permissions = await runQuery(`SELECT permission_id AS v, CONCAT(name,' — ',risk_level) AS t FROM permission ORDER BY FIELD(risk_level,'High','Medium','Low'), name`);
    return { devices, apps, vulns, analysts, permissions,
             enums: { STATUSES, SEVERITIES, PRIORITIES, RISKS, OS_TYPES, DEV_STATUS } };
  },

  async overview() {
    const counts = await runQuery(`
      SELECT (SELECT COUNT(*) FROM device) AS devices,(SELECT COUNT(*) FROM application) AS apps,
             (SELECT COUNT(*) FROM vulnerability) AS vulns,(SELECT COUNT(*) FROM incident) AS incidents,
             (SELECT COUNT(*) FROM incident WHERE status IN ('Open','Investigating')) AS open_incidents,
             (SELECT COUNT(*) FROM vulnerability WHERE severity='Critical') AS critical_vulns,
             (SELECT COUNT(*) FROM analyst) AS analysts`);
    const severity = await runQuery(`SELECT severity,COUNT(*) AS n FROM vulnerability GROUP BY severity ORDER BY FIELD(severity,'Critical','High','Medium','Low')`);
    const statuses = await runQuery(`SELECT status,COUNT(*) AS n FROM incident GROUP BY status ORDER BY FIELD(status,'Open','Investigating','Resolved','Closed')`);
    const workload = await runQuery(`SELECT * FROM v_analyst_workload ORDER BY total_incidents DESC`);
    return { counts, severity, statuses, workload };
  },

  // ---- DEVICES ----
  devices: () => runQuery(`
    SELECT d.device_id,d.name,d.os_type,d.os_version,d.owner_name,d.status,
           COUNT(a.app_id) AS app_count
    FROM device d LEFT JOIN application a ON a.device_id=d.device_id
    GROUP BY d.device_id,d.name,d.os_type,d.os_version,d.owner_name,d.status ORDER BY d.name`),
  addDevice: (b) => runQuery(`INSERT INTO device (name,os_type,os_version,owner_name,status) VALUES (${strReq(b.name,'Name')},${oneOf(b.os_type,OS_TYPES,'OS type')},${strReq(b.os_version,'OS version')},${strReq(b.owner_name,'Owner')},${oneOf(b.status,DEV_STATUS,'Status')})`),
  editDevice: (id, b) => runQuery(`UPDATE device SET name=${strReq(b.name,'Name')},os_type=${oneOf(b.os_type,OS_TYPES,'OS type')},os_version=${strReq(b.os_version,'OS version')},owner_name=${strReq(b.owner_name,'Owner')},status=${oneOf(b.status,DEV_STATUS,'Status')} WHERE device_id=${intReq(id,'device')}`),
  delDevice: (id) => runQuery(`DELETE FROM device WHERE device_id=${intReq(id,'device')}`),

  // ---- ANALYSTS ----
  analysts: () => runQuery(`
    SELECT an.analyst_id,an.name,an.email,an.role,
           COUNT(i.incident_id) AS incidents
    FROM analyst an LEFT JOIN incident i ON i.assigned_analyst_id=an.analyst_id
    GROUP BY an.analyst_id,an.name,an.email,an.role ORDER BY an.name`),
  addAnalyst: (b) => runQuery(`INSERT INTO analyst (name,email,role) VALUES (${strReq(b.name,'Name')},${strReq(b.email,'Email')},${strReq(b.role,'Role')})`),
  editAnalyst: (id, b) => runQuery(`UPDATE analyst SET name=${strReq(b.name,'Name')},email=${strReq(b.email,'Email')},role=${strReq(b.role,'Role')} WHERE analyst_id=${intReq(id,'analyst')}`),
  delAnalyst: (id) => runQuery(`DELETE FROM analyst WHERE analyst_id=${intReq(id,'analyst')}`),

  // ---- APPLICATIONS ----
  apps: () => runQuery(`
    SELECT a.app_id,a.app_name,a.publisher,a.version,d.name AS device_name,
           (SELECT COUNT(*) FROM app_permission ap WHERE ap.app_id=a.app_id) AS perm_count,
           (SELECT GROUP_CONCAT(p.name ORDER BY p.name SEPARATOR ', ') FROM app_permission ap JOIN permission p ON p.permission_id=ap.permission_id WHERE ap.app_id=a.app_id AND p.risk_level='High') AS high_risk,
           (SELECT COUNT(*) FROM vulnerability v WHERE v.app_id=a.app_id) AS vuln_count
    FROM application a JOIN device d ON d.device_id=a.device_id
    ORDER BY high_risk IS NULL, a.app_name`),
  addApp: (b) => runQuery(`INSERT INTO application (device_id,app_name,version,publisher,install_date) VALUES (${intReq(b.device_id,'Device')},${strReq(b.app_name,'App name')},${strReq(b.version,'Version')},${strReq(b.publisher,'Publisher')},${dateReq(b.install_date,'Install date')})`),
  delApp: (id) => runQuery(`DELETE FROM application WHERE app_id=${intReq(id,'app')}`),
  appPerms: (id) => runQuery(`
    SELECT p.permission_id,p.name,p.risk_level,
           EXISTS(SELECT 1 FROM app_permission ap WHERE ap.app_id=${intReq(id,'app')} AND ap.permission_id=p.permission_id) AS assigned
    FROM permission p ORDER BY FIELD(p.risk_level,'High','Medium','Low'),p.name`),
  assignPerm: (id, b) => runQuery(`INSERT IGNORE INTO app_permission (app_id,permission_id) VALUES (${intReq(id,'app')},${intReq(b.permission_id,'Permission')})`),
  unassignPerm: (id, pid) => runQuery(`DELETE FROM app_permission WHERE app_id=${intReq(id,'app')} AND permission_id=${intReq(pid,'permission')}`),

  // ---- PERMISSIONS (master list) ----
  permissions: () => runQuery(`
    SELECT p.permission_id,p.name,p.risk_level,
           (SELECT COUNT(*) FROM app_permission ap WHERE ap.permission_id=p.permission_id) AS used_by
    FROM permission p ORDER BY FIELD(p.risk_level,'High','Medium','Low'),p.name`),
  addPermission: (b) => runQuery(`INSERT INTO permission (name,risk_level) VALUES (${strReq(b.name,'Name')},${oneOf(b.risk_level,RISKS,'Risk level')})`),
  delPermission: (id) => runQuery(`DELETE FROM permission WHERE permission_id=${intReq(id,'permission')}`),

  // ---- VULNERABILITIES ----
  vulnerabilities: () => runQuery(`
    SELECT v.vuln_id,v.title,v.severity,v.cve_ref,
           DATE_FORMAT(v.discovered_date,'%Y-%m-%d') AS discovered_date,
           a.app_name,d.name AS device_name,
           (SELECT COUNT(*) FROM incident i WHERE i.vuln_id=v.vuln_id) AS incident_count
    FROM vulnerability v JOIN application a ON a.app_id=v.app_id JOIN device d ON d.device_id=a.device_id
    ORDER BY FIELD(v.severity,'Critical','High','Medium','Low'),v.title`),
  addVuln: (b) => runQuery(`INSERT INTO vulnerability (app_id,title,description,severity,cve_ref,discovered_date) VALUES (${intReq(b.app_id,'App')},${strReq(b.title,'Title')},${strOrNull(b.description)},${oneOf(b.severity,SEVERITIES,'Severity')},${strOrNull(b.cve_ref)},${dateReq(b.discovered_date,'Discovered date')})`),
  delVuln: (id) => runQuery(`DELETE FROM vulnerability WHERE vuln_id=${intReq(id,'vuln')}`),

  // ---- INCIDENTS ----
  incidents: () => runQuery(`${INCIDENT_SELECT} ORDER BY FIELD(i.status,'Open','Investigating','Resolved','Closed'),FIELD(v.severity,'Critical','High','Medium','Low')`),
  addIncident: (b) => runQuery(`INSERT INTO incident (vuln_id,assigned_analyst_id,title,status,priority) VALUES (${intReq(b.vuln_id,'Vulnerability')},${intOrNull(b.assigned_analyst_id)},${strReq(b.title,'Title')},${oneOf(b.status||'Open',STATUSES,'Status')},${oneOf(b.priority||'Medium',PRIORITIES,'Priority')})`),
  delIncident: (id) => runQuery(`DELETE FROM incident WHERE incident_id=${intReq(id,'incident')}`),
  history: (id) => runQuery(`SELECT history_id,action,old_status,new_status,changed_by,DATE_FORMAT(changed_at,'%Y-%m-%d %H:%i:%s') AS changed_at FROM incident_history WHERE incident_id=${intReq(id,'incident')} ORDER BY changed_at,history_id`),
  async setStatus(id, status) {
    const iid = intReq(id, 'incident');
    if (!STATUSES.includes(status)) throw new Error('invalid status');
    await runQuery(`UPDATE incident SET status=${str(status)} WHERE incident_id=${iid}`);
    const [row] = await runQuery(`${INCIDENT_SELECT} WHERE i.incident_id=${iid}`);
    return { incident: row, history: await api.history(iid) };
  },
};

// -----------------------------------------------------------------------------
// Routing
// -----------------------------------------------------------------------------
function sendJSON(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
const readBody = (req) => new Promise((resolve) => {
  let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve({}); } });
});
const ok = () => ({ ok: true });

// [method, regex, handler(matchGroups, body)]
const routes = [
  ['GET', /^\/api\/lists$/,            () => api.lists()],
  ['GET', /^\/api\/overview$/,         () => api.overview()],
  ['GET', /^\/api\/devices$/,          () => api.devices()],
  ['POST', /^\/api\/devices$/,         (m, b) => api.addDevice(b).then(ok)],
  ['PUT', /^\/api\/devices\/(\d+)$/,   (m, b) => api.editDevice(m[1], b).then(ok)],
  ['DELETE', /^\/api\/devices\/(\d+)$/,(m) => api.delDevice(m[1]).then(ok)],

  ['GET', /^\/api\/analysts$/,          () => api.analysts()],
  ['POST', /^\/api\/analysts$/,         (m, b) => api.addAnalyst(b).then(ok)],
  ['PUT', /^\/api\/analysts\/(\d+)$/,   (m, b) => api.editAnalyst(m[1], b).then(ok)],
  ['DELETE', /^\/api\/analysts\/(\d+)$/,(m) => api.delAnalyst(m[1]).then(ok)],

  ['GET', /^\/api\/apps$/,             () => api.apps()],
  ['POST', /^\/api\/apps$/,            (m, b) => api.addApp(b).then(ok)],
  ['DELETE', /^\/api\/apps\/(\d+)$/,   (m) => api.delApp(m[1]).then(ok)],
  ['GET', /^\/api\/apps\/(\d+)\/permissions$/,  (m) => api.appPerms(m[1])],
  ['POST', /^\/api\/apps\/(\d+)\/permissions$/, (m, b) => api.assignPerm(m[1], b).then(ok)],
  ['DELETE', /^\/api\/apps\/(\d+)\/permissions\/(\d+)$/, (m) => api.unassignPerm(m[1], m[2]).then(ok)],

  ['GET', /^\/api\/permissions$/,          () => api.permissions()],
  ['POST', /^\/api\/permissions$/,         (m, b) => api.addPermission(b).then(ok)],
  ['DELETE', /^\/api\/permissions\/(\d+)$/,(m) => api.delPermission(m[1]).then(ok)],

  ['GET', /^\/api\/vulnerabilities$/,          () => api.vulnerabilities()],
  ['POST', /^\/api\/vulnerabilities$/,         (m, b) => api.addVuln(b).then(ok)],
  ['DELETE', /^\/api\/vulnerabilities\/(\d+)$/,(m) => api.delVuln(m[1]).then(ok)],

  ['GET', /^\/api\/incidents$/,          () => api.incidents()],
  ['POST', /^\/api\/incidents$/,         (m, b) => api.addIncident(b).then(ok)],
  ['DELETE', /^\/api\/incidents\/(\d+)$/,(m) => api.delIncident(m[1]).then(ok)],
  ['GET', /^\/api\/incident\/(\d+)\/history$/,  (m) => api.history(m[1])],
  ['POST', /^\/api\/incident\/(\d+)\/status$/,  (m, b) => api.setStatus(m[1], b.status)],
];

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, `http://${req.headers.host}`).pathname;
  try {
    for (const [method, re, fn] of routes) {
      const m = p.match(re);
      if (m && req.method === method) {
        const body = (method === 'GET' || method === 'DELETE') ? {} : await readBody(req);
        return sendJSON(res, 200, await fn(m, body));
      }
    }
    // static
    const file = p === '/' ? '/index.html' : p;
    const full = path.join(__dirname, 'public', path.normalize(file).replace(/^(\.\.[/\\])+/, ''));
    if (fs.existsSync(full) && fs.statSync(full).isFile()) {
      res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream' });
      return fs.createReadStream(full).pipe(res);
    }
    res.writeHead(404); res.end('Not found');
  } catch (e) {
    sendJSON(res, 400, { error: e.message });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n  M-SHIELD console  →  http://localhost:${PORT}`);
  console.log(`  DB user: ${DB_USER}   schema: ${DB_NAME}   (Ctrl+C to stop)\n`);
});
