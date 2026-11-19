// Security event sink. One OCSF event per line (NDJSON), to stdout and to a
// dedicated security log file, kept separate from application/debug logs.
//
// Optimal-logging rules this enforces:
//   - structured, one event per line, machine-parseable
//   - a correlation id on every event so the WAF audit log and these app
//     events join on a single request
//   - security events only; never secrets, passwords, tokens or full PII
const fs = require('fs');
const path = require('path');

const LOG_DIR = process.env.APP_LOG_DIR || '/var/log/app';
const LOG_FILE = path.join(LOG_DIR, 'security.ndjson');

try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
} catch (e) {
  /* best effort */
}

let fileWriteWarned = false;

function emit(event, correlationId) {
  if (correlationId) {
    event.metadata = event.metadata || {};
    event.metadata.correlation_uid = correlationId;
  }
  const line = JSON.stringify(event);
  process.stdout.write(line + '\n');
  try {
    fs.appendFileSync(LOG_FILE, line + '\n');
  } catch (e) {
    // Never let logging break the request, but do not hide a broken file sink.
    // Warn once to stderr so a stale mount or permission fault is visible.
    if (!fileWriteWarned) {
      fileWriteWarned = true;
      process.stderr.write(
        '[logsting] security log file write failed (' + (e.code || e.message) +
        ' at ' + LOG_FILE + '); continuing with stdout only\n'
      );
    }
  }
  return event;
}

module.exports = { emit, LOG_FILE };
