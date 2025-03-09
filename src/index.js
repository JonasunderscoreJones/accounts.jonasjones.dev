function corsAccessControlAllowOrigin(request) {
	if (!request.headers.get('origin')) {
		return headersCORS
	}
	console.log("domain: ", request.headers.get('origin'))
	const url = new URL(request.headers.get('origin'))
	const { host } = url
	if (['localhost:5173'].includes(host)) {
		let corsHeaders = headersCORS
		corsHeaders['Access-Control-Allow-Origin'] = host
		console.log(corsHeaders)
		return corsHeaders
	}
	return headersCORS
}

const headersCORS = {
	'Access-Control-Allow-Origin': 'https://dash.jonasjones.dev',
	'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
	'Access-Control-Allow-Headers': 'Content-Type, Authorization',
	'Access-Control-Allow-Credentials': 'true'
};

export default {
	async fetch(request, env, ctx) {
	  const url = new URL(request.url);
	  const { pathname } = url;

	if (request.method === 'OPTIONS') {
		return new Response(null, { status: 200, headers: corsAccessControlAllowOrigin(request) });
	}

	  // Router
	  if (pathname === '/') {
		// redirect to account dashboard page
		return new Response(null, {
			status: 302,
			headers: { Location: 'https://dash.jonasjones.dev', },
		});
	  } else if (pathname === '/login' && request.method === 'POST') {
		return handleLogin(request, env);
	  } else if (pathname === '/register' && request.method === 'POST') {
		return handleRegister(request, env);
	  } else if (pathname === '/logout' && request.method === 'POST') {
		return handleLogout(request, env);
	  } else if (pathname === '/account' && request.method === 'GET') {
		return getAccountData(request, env);
	  } else if (pathname === '/account' && request.method === 'POST') {
		return updateAccountData(request, env);
	  } else if (pathname === '/session' && request.method === 'GET') {
		return sessionHealthCheck(request, env);
	  } else {
		return new Response('Not Found', { status: 404, headers: corsAccessControlAllowOrigin(request) });
	  }
	},
};

// Helpers
async function handleLogin(request, env, data = null) {
	// If no data is passed, parse the request JSON
	const { email, password } = data || await request.json();
	const db = env.DB;

	if (!email || !password) {
		return new Response('Bad Request', { status: 400, headers: corsAccessControlAllowOrigin(request) });
	}

	// Check user exists and validate password
	const userQuery = `
	  SELECT id, passwordhash, is_active FROM users WHERE email = ?;
	`;
	const user = await db.prepare(userQuery).bind(email).first();

	if (!user || !user.is_active) {
	  return new Response('Invalid email or account inactive.', { status: 403, headers: corsAccessControlAllowOrigin(request) });
	}

	const validPassword = await verifyPassword(password, user.passwordhash);
	if (!validPassword) {
	  return new Response('Invalid credentials.', { status: 403, headers: corsAccessControlAllowOrigin(request) });
	}

	// Create session
	const sessionKey = crypto.randomUUID();
	const created = formatDate(new Date());
	const expiration = formatDate(new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)); // 7 days later

	//TODO: Update last_login field in users table
	//TODO: Add entry to user_actions table for login, signup, etc.

	const sessionInsert = `
	  INSERT INTO sessions (created, expiration, userid, sessionkey)
	  VALUES (?, ?, ?, ?);
	`;
	await db.prepare(sessionInsert).bind(created, expiration, user.id, sessionKey).run();

	return new Response(JSON.stringify({ sessionKey, expiration }), { status: 200, headers: corsAccessControlAllowOrigin(request) });
}

async function handleRegister(request, env) {
	const data = await request.json(); // Read the body once
	const { username, password, email, firstname, lastname } = data;
	const db = env.DB;

	if (!username || !password, !email || !firstname || !lastname) {
		return new Response('Bad Request', { status: 400, headers: corsAccessControlAllowOrigin(request) });
	}

	// Hash password
	const passwordHash = await hashPassword(password);
	console.log(password, passwordHash)

	try {
	  const insertUser = `
		INSERT INTO users (created, username, passwordhash, email, first_name, last_name)
		VALUES (?, ?, ?, ?, ?, ?);
	  `;
	  const created = formatDate(new Date());
	  await db.prepare(insertUser).bind(created, username, passwordHash, email, firstname, lastname).run();

	  return handleLogin(request, env, data);
	} catch (error) {
	  if (error.message.includes('UNIQUE')) {
		return new Response('Username or email already exists.', { status: 409, headers: corsAccessControlAllowOrigin(request) });
	  }
	  console.log(error.message)
	  return new Response('Error registering user.', { status: 500, headers: corsAccessControlAllowOrigin(request) });
	}
}

async function handleLogout(request, env) {
	const { sessionKey } = await request.json();
	const db = env.DB;

	const deleteSession = `
	  DELETE FROM sessions WHERE sessionkey = ?;
	`;
	await db.prepare(deleteSession).bind(sessionKey).run();

	return new Response('Logged out successfully.', { status: 200, headers: corsAccessControlAllowOrigin(request) });
}

async function getAccountData(request, env) {
	const sessionKey = request.headers.get('Authorization')?.replace('Bearer ', '');
	if (!sessionKey) {
	  return new Response('Bad Request', { status: 400, headers: corsAccessControlAllowOrigin(request) });
	}

	const db = env.DB;

	const accountQuery = `
	  SELECT u.username, u.email, u.first_name, u.last_name
	  FROM users u
	  JOIN sessions s ON u.id = s.userid
	  WHERE s.sessionkey = ?;
	`;
	const account = await db.prepare(accountQuery).bind(sessionKey).first();

	if (!account) {
	  return new Response('Unauthorized', { status: 401, headers: corsAccessControlAllowOrigin(request) });
	}

	return new Response(JSON.stringify(account), { status: 200, headers: corsAccessControlAllowOrigin(request) });
}

async function updateAccountData(request, env) {
	const sessionKey = request.headers.get('Authorization')?.replace('Bearer ', '');
	const { username, password, email, first_name, last_name } = await request.json();
	const db = env.DB;

	if (!username || !email || !first_name || !last_name || !password) {
		return new Response('Bad Request', { status: 400, headers: corsAccessControlAllowOrigin(request) });
	}

	const passwordHash = await hashPassword(password);

	const updateAccount = `
	  UPDATE users
	  SET username = ?, passwordhash = ?, email = ?, first_name = ?, last_name = ?
	  WHERE id = (
		SELECT userid FROM sessions WHERE sessionkey = ?
	  );
	`;
	await db.prepare(updateAccount).bind(username, passwordHash, email, first_name, last_name, sessionKey).run();

	return new Response('Account updated successfully.', { status: 200, headers: corsAccessControlAllowOrigin(request) });
}

async function sessionHealthCheck(request, env) {
	const sessionKey = request.headers.get('Authorization')?.replace('Bearer ', '');
	if (!sessionKey) {
	  return new Response('Bad Request', { status: 400, headers: corsAccessControlAllowOrigin(request) });
	}

	const db = env.DB;

	const sessionQuery = `
	  SELECT expiration FROM sessions WHERE sessionkey = ?;
	`;
	const session = await db.prepare(sessionQuery).bind(sessionKey).first();

	if (!session) {
		return new Response(JSON.stringify({ valid: false, error: 'Invalid sessionKey.' }), { status: 401, headers: corsAccessControlAllowOrigin(request) });
	}

	if (new Date(session.expiration) < new Date()) {
		return new Response(JSON.stringify({ valid: false, error: 'Session expired.' }), { status: 401, headers: corsAccessControlAllowOrigin(request) });
	}

	return new Response(JSON.stringify({ valid: true, userId: session.userid }), { status: 200, headers: corsAccessControlAllowOrigin(request) });
}

// Utility functions
async function hashPassword(password) {
	const encoder = new TextEncoder();
	const data = encoder.encode(password);

	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
	return hashHex;
}

async function verifyPassword(password, hash) {
	const hashedPassword = await hashPassword(password);
	return hashedPassword === hash;
}

function formatDate(date) {
	return date.toISOString().replace('T', ' ').split('.')[0]; // Converts to 'YYYY-MM-DD HH:MM:SS'
}
