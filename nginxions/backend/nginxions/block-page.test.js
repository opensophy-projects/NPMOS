import assert from "node:assert/strict";
import { test } from "node:test";
import { render } from "./block-page.js";

const settings = {
	enabled: true,
	title: "Доступ <запрещён>",
	text: "Первый абзац\nвторая строка\n\nВторой абзац",
	contact: "",
	details: true,
	accent: "#123abc",
};

test("block page: escaped text, paragraphs, details for nginx to fill in", () => {
	const page = render(settings);
	assert.match(page, /<title>Доступ &lt;запрещён&gt;<\/title>/);
	assert.match(page, /<p>Первый абзац<br \/>вторая строка<\/p>/);
	assert.match(page, /<p>Второй абзац<\/p>/);
	assert.match(page, /--accent: #123abc/);
	for (const key of ["{{id}}", "{{ip}}", "{{host}}", "{{time}}"]) assert.ok(page.includes(key));
	assert.ok(!render({ ...settings, details: false }).includes("{{ip}}"));
});
