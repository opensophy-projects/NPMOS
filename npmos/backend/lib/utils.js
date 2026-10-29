// NPMOS: spawn instead of execFile (see spawnFile)
import { spawn } from "node:child_process";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Liquid } from "liquidjs";
import crypto from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import _ from "lodash";
import { debug, global as logger } from "../logger.js";
import errs from "./error.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const writeHash = async () => {
	const referencedEnvVars = new Set();
	const templateFiles = await readdir(`${__dirname}/../templates`);

	for (const fileName of templateFiles) {
		const content = await readFile(`${__dirname}/../templates/${fileName}`, "utf8");
		const matches = content.match(/env\.[A-Z0-9_]+/g) || [];

		for (const match of matches) {
			referencedEnvVars.add(match.replace("env.", ""));
		}
	}

	let hashInput = "";
	for (const varName of [...referencedEnvVars].sort()) {
		hashInput += process.env[varName] || "";
	}
	hashInput += process.env.TV;

	const hash = crypto.createHash("sha512").update(hashInput).digest("hex");
	await writeFile("/data/npmplus/env.sha512sum", hash);
};

/**
 * @param   {String} cmd
 * @param   {Array}  args
 * @returns {Promise}
 */
// NPMOS: execFile with stdin from /dev/null; rejects like execFile (err.stdout, err.stderr, err.code)
const spawnFile = (cmd, args = []) =>
	new Promise((resolve, reject) => {
		const child = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
		const out = [];
		const err = [];
		child.stdout.on("data", (d) => out.push(d));
		child.stderr.on("data", (d) => err.push(d));
		child.on("error", reject);
		child.on("close", (code, signal) => {
			const result = { stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() };
			if (code === 0) return resolve(result);
			reject(Object.assign(new Error(`Command failed: ${cmd} ${args.join(" ")}`), result, { code, signal }));
		});
	});

const execFile = async (cmd, args) => {
	debug(logger, `CMD: ${cmd} ${args ? args.join(" ") : ""}`);

	try {
		// NPMOS: stdin is /dev/null, not a pipe: the open-appsec attachment writes its debug lines to
		// fd 0 while nginx reads its configuration; into a pipe nobody reads, `nginx -t` blocks for good
		// once the pipe is full (many hosts)
		const { stdout, stderr } = await spawnFile(cmd, args);
		return `${stdout || ""}${stderr || ""}`.trim();
	} catch (err) {
		if (err && typeof err === "object") {
			throw new errs.CommandError(`${err.stdout || ""}${err.stderr || ""}`.trim(), 1, err);
		}
		throw err;
	}
};

/**
 * Used in objection query builder
 *
 * @param   {Array}  omissions
 * @returns {Function}
 */
const omitRow = (omissions) => {
	/**
	 * @param   {Object} row
	 * @returns {Object}
	 */
	return (row) => {
		return _.omit(row, omissions);
	};
};

/**
 * Used in objection query builder
 *
 * @param   {Array}  omissions
 * @returns {Function}
 */
const omitRows = (omissions) => {
	/**
	 * @param   {Array} rows
	 * @returns {Object}
	 */
	return (rows) => {
		rows.forEach((row, idx) => {
			rows[idx] = _.omit(row, omissions);
		});
		return rows;
	};
};

/**
 * @returns {Object} Liquid render engine
 */
const getRenderEngine = () => {
	const renderEngine = new Liquid({
		root: `${__dirname}/../templates/`,
	});

	/**
	 * nginxAccessRule expects the object given to have 2 properties:
	 *
	 * directive  string
	 * address    string
	 */
	renderEngine.registerFilter("nginxAccessRule", (v) => {
		if (typeof v.directive !== "undefined" && typeof v.address !== "undefined" && v.directive && v.address) {
			return `${v.directive} ${v.address};`;
		}
		return "";
	});

	return renderEngine;
};

export default { writeHash, execFile, omitRow, omitRows, getRenderEngine };
