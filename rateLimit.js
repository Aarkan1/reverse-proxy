const sqlite = require("sqlite3");
const db = new sqlite.Database("proxy.db");

const util = require("util");
db.all = util.promisify(db.all); // get all
// db.get = util.promisify(db.get) // get one
db.run = util.promisify(db.run); // insert/update/delete

let bannedIps = [];
let hackerIps = {};
let throttleIps = {};

// reset request counters in interval
setInterval(() => {
  hackerIps = {};
  throttleIps = {};
}, 20 * 1000);

const adminRoutes = [
  "/wp-login.php",
  "/wp-login",
  "/wp-admin",
  "/admin",
  "/login",
  "/auth/login",
  "/auth/admin",
  "/api/login",
  "/api/admin",
];

const initBannedIps = async () => {
  bannedIps = await db.all("SELECT banned_ips.ip FROM banned_ips");
  bannedIps = bannedIps.map((b) => b.ip);
};

const insertBannedIp = async (ip) => {
  bannedIps.push(ip);
  await db.run("INSERT INTO banned_ips VALUES(NULL, ?)", ip);
};

initBannedIps();

module.exports = function rateLimit(requestLimit, req, res) {
  if (bannedIps.includes(req.ip)) {
    res.statusCode = 403;
    res.end("Forbidden");
    return false;
  }

  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;

  if (adminRoutes.includes(req.url)) {
    console.log("potential hacker url:", req.url);

    // potential hacker request counter
    !hackerIps[ip] && (hackerIps[ip] = 0);
    hackerIps[ip]++;

    // add ip to banned list
    hackerIps[ip] > 10 && insertBannedIp(ip);
  }

  // ip request counter
  !throttleIps[ip] && (throttleIps[ip] = 0);
  throttleIps[ip]++;

  // timeout on to many requests
  if (throttleIps[ip] > requestLimit) {
    res.statusCode = 429;
    res.end("Too many requests");
    return false;
  }

  return true;
};