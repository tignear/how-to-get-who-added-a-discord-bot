const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const fetch = require("node-fetch");
const helmet = require("helmet");
require('dotenv').config();

/**
 * constants
 */
const OAUTH2_ENDPOINT = "https://discord.com/api/oauth2";
const OAUTH2_AUTHORIZATION_ENDPOINT = OAUTH2_ENDPOINT + "/authorize";
const OAUTH2_TOKEN_ENDPOINT = OAUTH2_ENDPOINT + "/token";
const OAUTH2_CURRENT_AUTHORIZATION_ENDPOINT = OAUTH2_ENDPOINT + "/@me";
const { CLIENT_ID, REDIRECT_URI, CLIENT_SECRET, SESSION_SECRET, SERVER_PORT, DEBUG } = process.env;
const DISALLOWED_FETCH_DEST = [
  "audio",
  "audioworklet",
  "embed",
  "empty",
  "font",
  "frame",
  "iframe",
  "image",
  "manifest",
  "object",
  "paintworklet",
  "report",
  "script",
  "serviceworker",
  "sharedworker",
  "style",
  "track",
  "video",
  "worker",
  "xslt"
];
const DISALLOWED_FETCH_MODE = [
  "cors",
  "no-cors",
  "same-origin",
  "websocket",
];
function build_url(endpoint, parameters) {
  return new URL("?" + new URLSearchParams([...Object.entries(parameters)]).toString(), endpoint).toString();
}
function generate_state() {
  return crypto.randomBytes(32).toString("base64url");
}
function get_fetch_metadata(req) {
  const site = req.header("sec-fetch-site");
  if (site == null) {
    return null;
  }
  return {
    site,
    dest: req.header("sec-fetch-dest"),
    mode: req.header("sec-fetch-mode"),
    user: req.header("sec-fetch-user"),
  };
}
function eq_set(as, bs) {
  if (as.size !== bs.size) return false;
  for (var a of as) if (!bs.has(a)) return false;
  return true;
}
/**
 * application code
 */
const app = express();
// use template engine to preventing HTML injection
app.set("view engine", "ejs");
app.use(helmet());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  cookie: {
    // prevents CSRF
    sameSite: "lax",
    // mitigates session hijack by XSS 
    httpOnly: true,
    // prevents session hijack by MITM
    // However, there is a blame for what to do if this is enabled when testing locally. 
    secure: process.env.NODE_ENV !== "development"
  },
  saveUninitialized: true,
  name: "sessionId"
}));

app.get('/', (_req, res) => {
  res.send('<a href="/login"> login </a>');
});

const SCOPE = ["identify", "email"];

app.get('/login', (req, res) => {
  function validate_fetch_metadata(req) {
    const meta = get_fetch_metadata(req);
    if (!meta) {
      return true;
    }
    if (["cross-site", "same-site"].includes(meta.site)) {
      return false;
    }
    if (DISALLOWED_FETCH_DEST.includes(meta.mode)) {
      return false;
    }
    if (DISALLOWED_FETCH_MODE.includes(meta.mode)) {
      return false;
    }
    if (meta.user != "?1") {
      return false;
    }
    return true;
  }
  if (!validate_fetch_metadata(req)) {
    res.status(400).send("invalid request");
    return;
  }
  const state = generate_state();
  const url = build_url(OAUTH2_AUTHORIZATION_ENDPOINT, {
    client_id: CLIENT_ID,
    response_type: "code",
    scope: SCOPE.join(" "),
    redirect_uri: REDIRECT_URI,
    prompt: ["none"].join(" "),
    state,
  });
  req.session.state = state;
  res.redirect(302, url);
});
async function callback_success(req, res) {
  const { state: sessionState } = req.session;
  const { state: queryState, code } = req.query;

  if (queryState == null || code == null) {
    res.status(400).send("insufficient query parameter");
    return;
  }
  try {
    // prevents session hijack by session fixation
    await new Promise((resolve, reject) => req.session.regenerate((err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    }));
  } catch (err) {
    console.error(err);
    res.status(500).send("internal server error!");
    return;
  }
  // prevent OAuth CSRF
  if (sessionState !== queryState) {
    res.status(400).send("invalid state");
    return;
  }
  const token_response = await fetch(OAUTH2_TOKEN_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI
    })
  });
  if (token_response.status !== 200) {
    res.status(500).send("failed to exchange code");
    return;
  }
  const token_response_data = await token_response.json();
  const { access_token, scope } = token_response_data;
  if (!eq_set(new Set(scope.split(" ")), new Set(SCOPE))) {
    res.status(400).send("insufficient granted scope");
    return;
  }
  const current_authorization = await fetch(OAUTH2_CURRENT_AUTHORIZATION_ENDPOINT, {
    headers: {
      "Authorization": `Bearer ${access_token}`,
    },
  });

  if (current_authorization.status !== 200) {
    res.status(500).send("failed to fetch authorization information");
    return;
  }
  const { user: { username, discriminator } } = await current_authorization.json();
  const data = {
    username,
    discriminator
  };
  res.render("./authorized.ejs", data);
}
async function callback(req, res) {
  if ("error" in req.query) {
    const { error } = req.query;
    res.render("./authorize_error.ejs", { error });
    return;
  }
  if ("code" in req.query) {
    await callback_success(req, res);
    return;
  }

  return res.status(400).send("invalid request");
}
app.get("/callback", (req, res) => {
  function validate_fetch_metadata(req) {
    const meta = get_fetch_metadata(req);
    if (!meta) {
      return true;
    }
    if (["same-origin", "same-site", "none"].includes(meta.site)) {
      return false;
    }
    if (DISALLOWED_FETCH_DEST.includes(meta.mode)) {
      return false;
    }
    if (DISALLOWED_FETCH_MODE.includes(meta.mode)) {
      return false;
    }
    return true;
  }
  if (!validate_fetch_metadata(req)) {
    res.status(400).send("invalid request");
    return;
  }
  callback(req, res).catch(err => {
    console.error(err);
  });
});
app.listen(SERVER_PORT);