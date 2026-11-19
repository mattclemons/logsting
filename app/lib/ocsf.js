// OCSF 1.1 event builders for the classes this reference service emits.
//
// Every event carries the Base Event classification attributes (category_uid,
// class_uid, activity_id, the derived type_uid) plus time, metadata and
// severity_id. type_uid = class_uid * 100 + activity_id.
//
// Classes used:
//   Authentication            3002  (category 3, IAM)
//   Web Resources Access      6004  (category 6, Application Activity)
//   API Activity              6003  (category 6, Application Activity)
//   Detection Finding         2004  (category 2, Findings)

const PRODUCT = { name: 'logsting', vendor_name: 'logsting-lab', version: '0.1.0' };
const SCHEMA_VERSION = '1.1.0';

// status_id: 0 Unknown, 1 Success, 2 Failure
// severity_id: 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical
const STATUS = { SUCCESS: 1, FAILURE: 2 };
const SEV = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };

function base(category_uid, class_uid, activity_id, severity_id, extra) {
  const now = Date.now();
  return Object.assign(
    {
      category_uid,
      class_uid,
      activity_id,
      type_uid: class_uid * 100 + activity_id,
      severity_id,
      time: now,
      // OCSF time_dt: RFC3339 string form of `time`. Kept so SIEMs and tools
      // that want a parseable timestamp (Chainsaw) have one.
      time_dt: new Date(now).toISOString(),
      metadata: { product: PRODUCT, version: SCHEMA_VERSION },
    },
    extra || {}
  );
}

function actor(user) {
  return user ? { user: { name: user } } : undefined;
}
function src(ip) {
  return ip ? { ip } : undefined;
}

// Authentication [3002], activity 1 = Logon
function authentication({ status_id, user, src_ip, severity_id, message }) {
  return base(3, 3002, 1, severity_id || SEV.INFO, {
    activity_name: 'Logon',
    status_id,
    actor: actor(user),
    src_endpoint: src(src_ip),
    message,
  });
}

// Web Resources Access Activity [6004], activity 1 = Read
function webResourceAccess({ status_id, user, src_ip, resource, decision, severity_id, message }) {
  return base(6, 6004, 1, severity_id || SEV.INFO, {
    activity_name: 'Read',
    status_id,
    actor: actor(user),
    src_endpoint: src(src_ip),
    web_resources: resource ? [{ name: resource }] : undefined,
    message: message,
    unmapped: decision ? { decision } : undefined,
  });
}

// API Activity [6003], activity_id passed by caller (0 Unknown, 1 Create, 2 Read, 3 Update, 4 Delete)
function apiActivity({ activity_id, status_id, user, src_ip, operation, severity_id, message, extra }) {
  return base(6, 6003, activity_id || 0, severity_id || SEV.INFO, {
    status_id,
    actor: actor(user),
    src_endpoint: src(src_ip),
    api: operation ? { operation } : undefined,
    message,
    unmapped: extra,
  });
}

// Detection Finding [2004], activity 1 = Create
function detectionFinding({ title, severity_id, user, src_ip, message, finding }) {
  return base(2, 2004, 1, severity_id || SEV.MEDIUM, {
    activity_name: 'Create',
    status_id: STATUS.SUCCESS,
    actor: actor(user),
    src_endpoint: src(src_ip),
    finding_info: { title, desc: message },
    message,
    unmapped: finding,
  });
}

module.exports = {
  STATUS,
  SEV,
  authentication,
  webResourceAccess,
  apiActivity,
  detectionFinding,
};
