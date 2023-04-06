const crypto = require("node:crypto");
const { URLSearchParams } = require("node:url");
const express = require("express");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");

const CONFIG = {
	port: 3000,
	client_id: "...",
	client_secret: "...",
	redirect_uri: "http://localhost:3000/oauthcallback",
};

const app = express();

app.use(cookieParser());

app.get("/connect", function (req, res) {
	const state = crypto.randomBytes(32).toString("hex");

	const url =
		"https://www.linkedin.com/oauth/v2/authorization?" +
		new URLSearchParams({
			client_id: CONFIG.client_id,
			redirect_uri: CONFIG.redirect_uri,
			state: state,
			response_type: "code",
			scope: "r_liteprofile,w_member_social,rw_organization_admin",
		});

	res.cookie("oauth_state", state, { httpOnly: true });
	res.redirect(url);
});

app.get("/oauthcallback", async function (req, res) {
	const { state, code } = req.query;
	const cookieState = req.cookies["oauth_state"];

	if (state !== cookieState) {
		return res.status(403).send("state mismatch"); // maybe CSRF
	}

	const tokenRes = await fetch("https://www.linkedin.com/oauth/v2/accessToken", {
		method: "POST",
		body: new URLSearchParams({
			client_id: CONFIG.client_id,
			client_secret: CONFIG.client_secret,
			redirect_uri: CONFIG.redirect_uri,
			code: code,
			grant_type: "authorization_code",
		}),
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
		},
	});

	const tokenData = await tokenRes.json();
	console.log("token data", tokenData);

	// {
	//   access_token: 'AQWuz...',
	//   expires_in: 5183999,
	//   refresh_token: 'AQWT2...',
	//   refresh_token_expires_in: 31535999,
	//   scope: 'r_liteprofile,rw_organization_admin,w_member_social'
	// }

	res.send("Connected successfully!");
});

app.post("/revoke", bodyParser.urlencoded({ extended: false }), async function (req, res) {
	const token = req.body.token;

	await fetch("https://www.linkedin.com/oauth/v2/revoke", {
		method: "POST",
		body: new URLSearchParams({
			client_id: CONFIG.client_id,
			client_secret: CONFIG.client_secret,
			token: token,
		}),
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
		},
	});

	res.send("Token revoked successfully!");
});

app.get("/userinfo", async function (req, res) {
	const accessToken = "..."; // TODO: authenticate the user and retrieve the access token

	const apiRes = await fetch(
		"https://api.linkedin.com/v2/me?projection=(localizedFirstName, localizedLastName)",
		{
			headers: {
				Authorization: `Bearer ${accessToken}`,
			},
		}
	);

	const userinfo = await apiRes.json();

	res.send(userinfo);
});

app.get("/", function (req, res) {
	res.sendFile(__dirname + "/index.html");
});

app.listen(CONFIG.port, function () {
	console.log(`Server listening at http://localhost:${CONFIG.port}`);
});
