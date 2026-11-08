import { migrate as logger } from "../../logger.js";

const migrateName = "nginxions_waf_objects";

/**
 * Objects of the open-appsec policy (WAF → Policy, docs/ROADMAP.md phase 5; ADR-0008), the objects
 * a host uses, and versions of the policy (a snapshot of objects, default policy and host settings
 * for a rollback).
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	await knex.schema.createTable("nginxions_waf_object", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.dateTime("modified_on").notNull();
		// threat_prevention | access_control | log_trigger | custom_response | exception |
		// trusted_sources | source_identifiers
		table.string("kind", 32).notNull();
		table.string("name", 100).notNull();
		table.string("description", 500).notNull().defaultTo("");
		// the object in the terms of v1beta2 without its name
		table.json("spec").notNull();
		// built-in (nginxions-*): read-only, updated with NginxionS
		table.boolean("builtin").notNull().defaultTo(false);
		table.unique(["kind", "name"]);
	});
	await knex.schema.alterTable("nginxions_waf_host", (table) => {
		// objects of the host's rule {template?, threatPreventionPractices?: [id], ...}; absent: as
		// the default policy
		table.json("objects").nullable();
	});
	await knex.schema.createTable("nginxions_waf_policy_version", (table) => {
		table.increments().primary();
		table.dateTime("created_on").notNull();
		table.integer("user_id").unsigned().nullable();
		table.string("comment", 255).notNull().defaultTo("");
		// objects, default policy and WAF settings of hosts after the change
		table.json("state").notNull();
	});
	logger.info(
		`[${migrateName}] nginxions_waf_object, nginxions_waf_host.objects, nginxions_waf_policy_version created`,
	);
};

const down = async (knex) => {
	await knex.schema.dropTable("nginxions_waf_policy_version");
	await knex.schema.alterTable("nginxions_waf_host", (table) => {
		table.dropColumn("objects");
	});
	await knex.schema.dropTable("nginxions_waf_object");
};

export { down, up };
