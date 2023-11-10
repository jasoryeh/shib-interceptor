const { JSDOM } = require('jsdom');
const axios = require('axios');
const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');

function logRequest(req, i = 0) {
    console.log(`Request ${i}: ${req.config.method} ${req.config.url} | ${req.status} ${req.statusText}`);
    return req;
}

function debug(name, item) {
    console.log(`${name}: ------------------------------------------------------------------------------`);
    console.log(item);
    console.log(`END ${name}: ------------------------------------------------------------------------------`);
    return item;
}

function getCookies(req) {
    if (!req.headers.has('set-cookie')) {
        return {};
    }
    var settedCookies = req.headers.get('set-cookie');
    settedCookies = (typeof settedCookies) == 'string' ? [settedCookies] : settedCookies;
    var sessionCookies = settedCookies
                            .map(each => {
                                var cookieNoData = each.trim().split(';', 1)[0];
                                var [k, ...vs] = cookieNoData.split('=');
                                return [k, vs.join('=')];
                            });
    var cookies = {};
    for (let [k, v] of sessionCookies) {
        cookies[k] = v;
    }
    return cookies;
}

function trackCookies(req, reqCookies) {
    var cookies = getCookies(req);
    for (let k in cookies) {
        if (k in reqCookies) {
            console.log(`Overwriting cookie ${k} => ${cookies[k]} \n was ${reqCookies[k]}`)
        }
        reqCookies[k] = cookies[k];
    }
    return cookies;
}

function getTrackedCookiesHeader(reqCookies) {
    var cookieStrings = [];
    for (let k in reqCookies) {
        cookieStrings.push(`${k}=${reqCookies[k]}`);
    }
    return cookieStrings;
}


async function axiosGet(site, reqCookies, referer = null) {
    let ax_params = {
        method: 'GET',
        maxRedirects: 0,
        url: site,
        validateStatus: () => true,
        headers: {
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-fetch-site": "none",
            "accept-encoding": "gzip, deflate, br",
            "sec-fetch-mode": "navigate",
            "accept-language": "en-US,en;q=0.9",
            "sec-fetch-dest": "document",
            cookie: getTrackedCookiesHeader(reqCookies),
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)'
        }
    };
    if (referer) {
        ax_params.headers.referer = referer;
    }
    let req = await axios(ax_params);
    trackCookies(req, reqCookies);
    return req;
}


async function axiosPostURLEncoded(site, body, reqCookies, referer = null) {
    let ax_params = {
        method: 'POST',
        maxRedirects: 0,
        url: site,
        validateStatus: () => true,
        headers: {
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "sec-fetch-site": "none",
            "accept-encoding": "gzip, deflate, br",
            "sec-fetch-mode": "navigate",
            "accept-language": "en-US,en;q=0.9",
            "sec-fetch-dest": "document",
            'content-type': 'application/x-www-form-urlencoded',
            cookie: getTrackedCookiesHeader(reqCookies),
            'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)'
        },
        data: body
    };
    if (referer) {
        ax_params.headers.referer = referer;
    }
    let req = await axios(ax_params);
    trackCookies(req, reqCookies);
    return req;
}

function getRedirectLocation(req) {
    if (!req.headers.location) {
        throw new Error("No redirect location!");
    }
    return req.headers.location;
}

function buildRequestUrlFromRequestAndPath(oldRequest, path) {
    var parsed = new URL(oldRequest.config.url);
    return new URL(parsed.origin + path);
}

async function logIn(samlURL, username, password) {
    var reqCookies = {};
    var req3 = logRequest(await axiosGet(samlURL, reqCookies), 3) // get uci shib login url from page we are logging in to

    var req4 = logRequest(await axiosGet(getRedirectLocation(req3), reqCookies, req3.config.url), 4); // shib - /idp/profile/SAML2/Redirect/SSO?SAMLRequest=

    var req5_url = buildRequestUrlFromRequestAndPath(req4, getRedirectLocation(req4)).href;
    var req5 = logRequest(await axiosGet(req5_url, reqCookies, req4.config.url), 5); // shib - /idp/profile/SAML2/Redirect/SSO;jsessionid=?execution=
    var req5_parse = new JSDOM(req5.data);

    // req6 (5's load) validates that session and persistence of sessions are working
    //var req6_url = req5.config.url; //to same as req5 (but should be taken from a form named "form1" on the page
    var req6_url = req5.config.url;
    var req6_body = new URLSearchParams();
    req6_body.set('shib_idp_ls_exception.shib_idp_session_ss', '');
    req6_body.set('shib_idp_ls_success.shib_idp_session_ss', 'true');
    req6_body.set('shib_idp_ls_value.shib_idp_session_ss', '');
    req6_body.set('shib_idp_ls_exception.shib_idp_persistent_ss', '');
    req6_body.set('shib_idp_ls_success.shib_idp_persistent_ss', 'true');
    req6_body.set('shib_idp_ls_value.shib_idp_persistent_ss', '');
    req6_body.set('shib_idp_ls_supported', 'true');
    req6_body.set('_eventId_proceed', '');
    var req6 = logRequest(await axiosPostURLEncoded(req6_url, req6_body, reqCookies, req5.config.url), 6) // shib - POST after JS

    var req7_url = buildRequestUrlFromRequestAndPath(req6, getRedirectLocation(req6)).href;
    var req7 = logRequest(await axiosGet(req7_url, reqCookies, req6.config.url), 7); // shib - load login page

    var req8_url = req7.config.url;
    var req8_body = new URLSearchParams();
    req8_body.set('referer', '');
    req8_body.set('return_url', '');
    req8_body.set('info_text', '');
    req8_body.set('info_url', '');
    req8_body.set('submit_type', '');
    req8_body.set('j_username', username);
    req8_body.set('j_password', password);
    req8_body.set('_eventId_proceed', 'Logging in');
    var req8 = logRequest(await axiosPostURLEncoded(req8_url, req8_body, reqCookies, req7.config.url), 8); // post login data

    var req9_url = buildRequestUrlFromRequestAndPath(req8, getRedirectLocation(req8)).href;
    var req9 = logRequest(await axiosGet(req9_url, reqCookies, req8.config.url), 9); // gets to duo here
    var req9_parse = new JSDOM(req9.data);
    var req9_duoelement = req9_parse.window.document.getElementsByClassName("duo-wrapper")[0].outerHTML;
    req9_duoelement = req9_duoelement.replaceAll("=\"/", "=\"" + (new URL(req9.config.url)).origin + "/");
    req9_duoelement = req9_duoelement.replaceAll("data-post-action=\"" + (new URL(req9.config.url)).origin, "data-post-action=\"");
    return [req9_duoelement, req9.config.url, reqCookies];
}

async function resumeLogIn(url, sig_response, reqCookies) {
    var req10_body = new URLSearchParams();
    req10_body.set('_eventId', 'proceed');
    req10_body.set('sig_response', sig_response);
    var req10 = logRequest(await axiosPostURLEncoded(url, req10_body, reqCookies, url), 10);

    var req11_url = buildRequestUrlFromRequestAndPath(req10, getRedirectLocation(req10)).href;
    var req11 = logRequest(await axiosGet(req11_url, reqCookies, req10.config.url), 11);

    var req12_url = req11_url; // get from form with attr name=form1
    var req12_body = new URLSearchParams();
    req12_body.set("shib_idp_ls_exception.shib_idp_session_ss", "");
    req12_body.set("shib_idp_ls_success.shib_idp_session_ss", "true");
    req12_body.set("_eventId_proceed", "");
    var req12 = logRequest(await axiosPostURLEncoded(req12_url, req12_body, reqCookies, req11.config.url), 12);

    var req12_parse = new JSDOM(req12.data);
    var req12_form = req12_parse.window.document.querySelector('form').outerHTML;
    return req12_form;
}


app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/', async(req, res) => {
    var page = `
    <html>
        <head>
            <title>Shibboleth Interceptor</title>
            <style>
                html {
                    font-family: Calibri, sans-serif;
                }
                label {
                    font-weight: bold;
                }
                input {
                    padding: 10px;
                    margin-bottom: 1rem;
                    margin-top: 0.25rem;
                    width: 100%;
                }
                #form {
                    width: 50%;
                    margin: auto;
                    margin-top: 10vh;
                }
            </style>
        </head>
        <body>
            <div id="form">
                <h1>Test Shibboleth Interceptor</h1>
                <form action="/login" method="POST">
                    <label for="url">URL</label><br>
                    <input type="text" id="url" name="url" value="https://canvas.eee.uci.edu/login/saml"><br>
                    <label for="user">Username</label><br>
                    <input type="text" id="user" name="user"><br>
                    <label for="pass">Password</label><br>
                    <input type="text" id="pass" name="pass"><br>
                    <label for="callback">Callback</label><br>
                    <input type="text" id="calback" name="callback" value="/callback"><br><br>
                    <input type="submit" value="Submit">
                </form>
            </div>
        </body>
    </html>`;
    return res.send(page);
});

async function handleLogIn(url, user, pass, callback, req, res) {
    //let authing = await logIn("https://canvas.eee.uci.edu/login/saml", "ptanteater", "iloveants");
    if (!url || !user || !pass || !callback || !req || !res) {
        return res.send("Need a callback, url, user, pass!");
    }
    let authing = await logIn(url, user, pass);
    res.cookie('saml-callback-to', callback)
    res.cookie('saml-memory', authing[1]);
    var cookies_wrap = JSON.stringify(authing[2]);
    res.cookie('saml-cookies', cookies_wrap);
    debug("DUO ELEMENT", authing[0]);
    return res.send(authing[0]);
}

app.get('/login', async (req, res) => {
    return await handleLogIn(req.query.url, req.query.user, req.query.pass, req.query.callback, req, res);
});

app.post('/login', async (req, res) => {
    console.log(req.body);
    return await handleLogIn(req.body.url, req.body.user, req.body.pass, req.body.callback, req, res);
});

function addDataTo(arr, elem) {
    var data = {};
    data['tag'] = elem.tagName;
    for (let name of elem.getAttributeNames()) {
        data[name] = elem.getAttribute(name);
    }
    arr.push(data);
    for (let children of elem.children) {
        addDataTo(arr, children);
    }
    return arr;
}

app.post('/idp/profile/SAML2/Redirect/SSO*', async (req, res) => {
    debug("DUO AUTH", req.body);
    debug("AUTH COOKIES", req.cookies);

    var saml_url = req.cookies['saml-memory'];
    if (!saml_url) {
        return res.send("no saml memory cookie");
    }
    var callback_url = req.cookies['saml-callback-to']; // a url to forward this data to...
    if (!callback_url) {
        return res.send("no callback url");
    }

    var reqCookies = JSON.parse(req.cookies['saml-cookies']);
    let authdone = await resumeLogIn(saml_url, req.body.sig_response, reqCookies);
    debug("AUTH COMPLETE", authdone);

    res.cookie('saml-sig', JSON.stringify(req.body));
    res.set('Content-Type', 'text/html');
    
    // parse data
    var response = {
        "response": authdone,
        "extracted": {
            "main": { },
            "fields": [ ]
        },
    };
    var parsed = new JSDOM(authdone).window.document.body.children[0];
    for (let name of parsed.getAttributeNames()) {
        response['extracted']['main'][name] = parsed.getAttribute(name);
    }
    addDataTo(response['extracted']['fields'], parsed);

    // convert
    var response_json = JSON.stringify(response);
    var response_buffer = Buffer.from(response_json);
    return res.send(`
    <html>
        <head>
            <title>Authenticating...</title>
        </head>
        <body onload="document.forms[0].submit()">
            <form action="${callback_url}" method="POST">
                <input name="auth_data" value="${response_buffer.toString('base64')}"></input>
                <input type="submit" value="Continue"/>
            </form>
        </body>
     </html>
     `);
});

app.post('/callback', async (req, res) => {
    var raw = req.body.auth_data;
    debug("CALLBACK RAW", req.body);
    var rawbuffer = Buffer.from(raw, 'base64');
    var rawjson = JSON.parse(rawbuffer.toString());
    debug("CALLBACK DATA", rawjson);
    res.set('Content-Type', 'application/json');
    return res.send(rawjson);
});

const PORT = process.env.PORT ?? 1234;
app.listen(PORT, () => {
    console.log(`Listening: ${PORT}`);
});