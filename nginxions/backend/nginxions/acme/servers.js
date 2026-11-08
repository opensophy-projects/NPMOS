// ACME servers (Settings → ACME; Certificates → ACME chooses one for each certificate). A preset (Let's Encrypt,
// ZeroSSL, Google Trust Services, SSL.com, the TLS CA of the Russian Federation…) or a server of your own (step-ca,
// an internal CA, any RFC 8555 server). Each server says which ACME client NginxionS runs for it: certbot (the one of
// NPMplus, its DNS plugins) or lego (an ES256 account key and the name in the CN of the CSR: some CAs refuse the RSA
// account of certbot or a CSR without a subject). Before: one server for all, in env settings (ACME_SERVER…): those
// settings become the first server of the list, the default one.
import db from "../../db.js";
import errs from "../../lib/error.js";
import { certbot as logger } from "../../logger.js";
import { decrypt, encrypt } from "../secrets.js";

export const TABLE = "nginxions_acme_server";
export const CLIENTS = ["certbot", "lego"];
// shown instead of a secret that is set; sent back unchanged it keeps the secret
export const SECRET_SET = "********";

/**
 * Known servers. eab: "required" (the keys of the account page of the CA), "auto" (ZeroSSL issues them for the
 * email), "" (not needed). client: the client the server works with; lego_only: certbot cannot register there.
 */
export const PRESETS = [
	{
		id: "letsencrypt",
		name: "Let's Encrypt",
		directory: "https://acme-v02.api.letsencrypt.org/directory",
		client: "certbot",
		eab: "",
		profiles: ["classic", "tlsserver", "shortlived"],
	},
	{
		id: "letsencrypt-staging",
		name: "Let's Encrypt (staging)",
		directory: "https://acme-staging-v02.api.letsencrypt.org/directory",
		client: "certbot",
		eab: "",
		profiles: ["classic", "tlsserver", "shortlived"],
	},
	{ id: "zerossl", name: "ZeroSSL", directory: "https://acme.zerossl.com/v2/DV90", client: "certbot", eab: "auto" },
	{
		id: "google",
		name: "Google Trust Services",
		directory: "https://dv.acme-v02.api.pki.goog/directory",
		client: "certbot",
		eab: "required",
	},
	{
		id: "sslcom",
		name: "SSL.com",
		directory: "https://acme.ssl.com/sslcom-dv-ecc",
		client: "certbot",
		eab: "required",
	},
	{
		// the TLS CA of the Russian Federation, public test stage (a non-production chain): it accepts only ES256
		// account keys and needs the name in the CN of the CSR, which certbot does not do
		id: "tlscc-stage",
		name: "ТЦИ / НУЦ Минцифры (stage)",
		directory: "https://acme.stage.tlscc.ru/directory",
		client: "lego",
		eab: "",
		lego_only: true,
		caa: "stage.tlscc.ru",
	},
];

const presetOf = (id) => PRESETS.find((p) => p.id === id);
const presetByDirectory = (url) => PRESETS.find((p) => p.directory === url);

const URL_FORM = /^https?:\/\/[A-Za-z0-9._~:/?&%+@=-]+$/;
const EMAIL_FORM = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}$/;
const TOKEN_FORM = /^[A-Za-z0-9_=+/-]{0,512}$/;
const PROFILE_FORM = /^[A-Za-z0-9._-]{0,40}$/;

const hmacOf = (row) => {
	if (!row?.eab_hmac_key_enc) return "";
	try {
		return decrypt(row.eab_hmac_key_enc);
	} catch {
		return "";
	}
};

/** the row with its secret, for the clients (never sent to the browser) */
const internal = (row) =>
	row && {
		id: row.id,
		name: row.name,
		preset: row.preset,
		directory: row.directory,
		client: row.client,
		email: row.email || "",
		eab_kid: row.eab_kid || "",
		eab_hmac_key: hmacOf(row),
		profile: row.profile || "",
		tls_verify: !!row.tls_verify,
		is_default: !!row.is_default,
	};

/** the row for the API: the secret masked */
const shown = (row, used = 0) => {
	const s = internal(row);
	return { ...s, eab_hmac_key: s.eab_hmac_key ? SECRET_SET : "", used_by: used };
};

/** the first server from the env settings of before (ACME_SERVER, ACME_EMAIL, ACME_EAB_*, ACME_PROFILE) */
const fromEnv = (env = process.env) => {
	const directory = env.ACME_SERVER || PRESETS[0].directory;
	const preset = presetByDirectory(directory);
	const profile = env.ACME_PROFILE && env.ACME_PROFILE !== "none" ? env.ACME_PROFILE : "";
	return {
		name: preset?.name || new URL(directory).host,
		preset: preset?.id || "custom",
		directory,
		client: preset?.client || "certbot",
		email: env.ACME_EMAIL || "",
		eab_kid: env.ACME_EAB_KID || "",
		eab_hmac_key_enc: env.ACME_EAB_HMAC_KEY ? encrypt(env.ACME_EAB_HMAC_KEY) : null,
		profile,
		tls_verify: env.ACME_SERVER_TLS_VERIFY !== "false",
		is_default: true,
	};
};

let seeding = null;
/** an empty list gets the server of the env settings, so that existing certificates and the hosts keep working */
const seed = async () => {
	if (!seeding) {
		seeding = (async () => {
			const [{ count }] = await db()(TABLE).count({ count: "*" });
			if (Number(count) === 0) await db()(TABLE).insert(fromEnv());
		})().finally(() => {
			seeding = null;
		});
	}
	await seeding;
};

/** how many ACME certificates use each server: {<server id>: n}; the default one counts those without an id */
const usage = async (defaultId) => {
	const rows = await db()("certificate").where({ is_deleted: 0, provider: "letsencrypt" }).select("meta");
	const out = {};
	for (const r of rows) {
		let meta = r.meta;
		try {
			if (typeof meta === "string") meta = JSON.parse(meta || "{}");
		} catch {
			meta = {};
		}
		const id = Number(meta?.acme_server_id) || defaultId;
		if (id) out[id] = (out[id] || 0) + 1;
	}
	return out;
};

/**
 * Validates a server from the API.
 * @param {object} body
 * @param {object} [current]  the stored server (internal form) when it is changed
 */
export const normalize = (body, current) => {
	const preset = presetOf(body.preset ?? current?.preset ?? "custom");
	const directory = String(preset ? preset.directory : (body.directory ?? current?.directory ?? "")).trim();
	if (!URL_FORM.test(directory))
		throw new errs.ValidationError("The directory URL of the ACME server must start with https:// or http://");
	const client = String(body.client ?? current?.client ?? preset?.client ?? "certbot");
	if (!CLIENTS.includes(client)) throw new errs.ValidationError("The ACME client is certbot or lego");
	if (preset?.lego_only && client !== "lego")
		throw new errs.ValidationError(`${preset.name} works only with lego: certbot cannot register an account there`);
	const email = String(body.email ?? current?.email ?? "").trim();
	if (email && !EMAIL_FORM.test(email)) throw new errs.ValidationError("The email is not valid");
	const kid = String(body.eab_kid ?? current?.eab_kid ?? "").trim();
	let hmac =
		body.eab_hmac_key === undefined || body.eab_hmac_key === SECRET_SET
			? (current?.eab_hmac_key ?? "")
			: String(body.eab_hmac_key).trim();
	if (!kid) hmac = "";
	if (!TOKEN_FORM.test(kid) || !TOKEN_FORM.test(hmac))
		throw new errs.ValidationError("The EAB keys have characters they cannot have");
	if (!!kid !== !!hmac) throw new errs.ValidationError("The EAB key ID and the HMAC key go together");
	if (preset?.eab === "required" && !kid)
		throw new errs.ValidationError(`${preset.name} needs the EAB keys of your account`);
	if ((preset?.eab === "auto" || kid) && !email)
		throw new errs.ValidationError("An email is needed with EAB and ZeroSSL");
	const profile = String(body.profile ?? current?.profile ?? "").trim();
	if (!PROFILE_FORM.test(profile))
		throw new errs.ValidationError("The profile is a name of letters, digits, '.', '_' or '-'");
	const name = String(body.name ?? current?.name ?? preset?.name ?? "").trim() || new URL(directory).host;
	if (name.length > 100) throw new errs.ValidationError("The name is too long");
	return {
		name,
		preset: preset?.id || "custom",
		directory,
		client,
		email,
		eab_kid: kid,
		eab_hmac_key_enc: hmac ? encrypt(hmac) : null,
		profile,
		tls_verify: body.tls_verify ?? current?.tls_verify ?? true,
	};
};

const servers = {
	/** all servers (secrets masked) and the presets */
	list: async () => {
		await seed();
		const rows = await db()(TABLE).orderBy("id");
		const def = rows.find((r) => r.is_default) || rows[0];
		const used = await usage(def?.id);
		return {
			items: rows.map((r) => shown({ ...r, is_default: r.id === def?.id }, used[r.id] || 0)),
			presets: PRESETS,
			clients: CLIENTS,
		};
	},

	/** a server with its secret, for the clients; null when there is none */
	get: async (id) => {
		await seed();
		return internal(await db()(TABLE).where("id", Number(id)).first()) || null;
	},

	/** the default server (internal form) */
	default: async () => {
		await seed();
		const row = (await db()(TABLE).where("is_default", true).first()) || (await db()(TABLE).orderBy("id").first());
		return internal(row);
	},

	/**
	 * The server of a certificate: meta.acme_server_id, the default one for certificates of before; a server that
	 * was removed meanwhile fails with its id.
	 */
	of: async (meta = {}) => {
		const id = Number(meta?.acme_server_id) || 0;
		if (!id) return servers.default();
		const server = await servers.get(id);
		if (!server) throw new errs.ValidationError(`The ACME server #${id} of this certificate was removed`);
		return server;
	},

	create: async (body) => {
		await seed();
		const row = normalize(body);
		const [id] = await db()(TABLE)
			.insert({ ...row, is_default: false })
			.returning("id");
		const created = await servers.get(typeof id === "object" ? id.id : id);
		if (body.is_default) await servers.setDefault(created.id);
		return shown(await db()(TABLE).where("id", created.id).first());
	},

	update: async (id, body) => {
		const current = await servers.get(id);
		if (!current) throw new errs.ItemNotFoundError(id);
		await db()(TABLE)
			.where("id", current.id)
			.update({ ...normalize(body, current), modified_on: db().fn.now() });
		if (body.is_default) await servers.setDefault(current.id);
		return shown(await db()(TABLE).where("id", current.id).first());
	},

	setDefault: async (id) => {
		const current = await servers.get(id);
		if (!current) throw new errs.ItemNotFoundError(id);
		await db().transaction(async (trx) => {
			await trx(TABLE).update({ is_default: false });
			await trx(TABLE).where("id", current.id).update({ is_default: true });
		});
		return shown(await db()(TABLE).where("id", current.id).first());
	},

	/** a server no certificate uses; the default one stays */
	remove: async (id) => {
		const current = await servers.get(id);
		if (!current) throw new errs.ItemNotFoundError(id);
		const def = await servers.default();
		if (def?.id === current.id)
			throw new errs.ValidationError("The default ACME server cannot be removed: choose another default first");
		const used = (await usage(def?.id))[current.id] || 0;
		if (used)
			throw new errs.ValidationError(
				`${used} certificate(s) are issued by this ACME server: remove or reissue them first`,
			);
		await db()(TABLE).where("id", current.id).delete();
		return { ok: true };
	},

	/** values of the secrets of all servers, masked in logs */
	secrets: async () => {
		try {
			const rows = await db()(TABLE).whereNotNull("eab_hmac_key_enc");
			return rows.map(hmacOf).filter((v) => v.length >= 6);
		} catch {
			return [];
		}
	},
};

/** at the start: the server of the env settings of before becomes the first one, never fails the start */
export const bootstrap = async () => {
	try {
		await seed();
	} catch (err) {
		logger.warn(`ACME servers: ${err.message}`);
	}
};

export default servers;
