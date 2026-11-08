// The project was called NPMOS: its tables were npmos_*, its migrations *_npmos_*.js and the names of its
// built-in WAF objects npmos-*. A database of that time is brought to the names of NginxionS once, before the
// migrations run (knex refuses a database whose migrations table names files that do not exist).
import { migrate as logger } from "../logger.js";

const OLD = "npmos";
const NEW = "nginxions";

/** @param {import("knex").Knex} knex */
export const renameFromNpmos = async (knex) => {
	if (!(await knex.schema.hasTable("migrations"))) return;
	const old = await knex("migrations").where("name", "like", `%_${OLD}_%`).count({ n: "*" }).first();
	if (!Number(old?.n)) return;
	logger.info("renaming the database of NPMOS to the names of NginxionS");
	await knex.transaction(async (trx) => {
		await trx("migrations").update({ name: trx.raw("replace(name, ?, ?)", [`_${OLD}_`, `_${NEW}_`]) });
		const pg = /^(pg|postgres)/.test(trx.client.config.client);
		const tables = pg
			? (
					await trx.raw(
						"select table_name as name from information_schema.tables where table_schema = current_schema()",
					)
				).rows.map((r) => r.name)
			: [];
		for (const table of tables.filter((t) => t.startsWith(`${OLD}_`))) {
			const renamed = NEW + table.slice(OLD.length);
			await trx.schema.renameTable(table, renamed);
			// names of built-in objects (npmos-recommended…) and of files kept in text and JSON columns
			const columns = (
				await trx.raw(
					`select column_name as name, data_type as type from information_schema.columns
					 where table_schema = current_schema() and table_name = ? and data_type in ('text', 'character varying', 'json', 'jsonb')`,
					[renamed],
				)
			).rows;
			for (const { name, type } of columns) {
				const cast = type === "json" || type === "jsonb" ? `::${type}` : "";
				await trx.raw(`update ?? set ?? = replace(??::text, ?, ?)${cast} where ??::text like ?`, [
					renamed,
					name,
					name,
					OLD,
					NEW,
					name,
					`%${OLD}%`,
				]);
			}
		}
		// our keys in the JSON of tables of NPMplus (meta.npmos_csr of certificates, npmos_geo of hosts…)
		const json = pg
			? (
					await trx.raw(
						`select table_name as t, column_name as c, data_type as type from information_schema.columns
						 where table_schema = current_schema() and data_type in ('json', 'jsonb') and table_name not like ?`,
						[`${NEW}\\_%`],
					)
				).rows
			: [];
		for (const { t, c, type } of json) {
			await trx.raw(`update ?? set ?? = replace(??::text, ?, ?)::${type} where ??::text like ?`, [
				t,
				c,
				c,
				`"${OLD}_`,
				`"${NEW}_`,
				c,
				`%"${OLD}\\_%`,
			]);
		}
	});
};
