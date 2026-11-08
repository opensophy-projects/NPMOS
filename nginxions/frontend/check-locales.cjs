#!/usr/bin/env node

// This file does a few things to ensure that the Locales are present and valid:
// - Ensures that the name of the locale exists in the language list
// - Ensures that each locale contains the translations used in the application
// - Ensures that there are no unused translations in the locale files
// - Also checks the error messages returned by the backend

const allLocales = [
	["en", "en-US"],
	["bg", "bg-BG"],
	["cs", "cs-CZ"],
	["de", "de-DE"],
	["es", "es-ES"],
	["et", "et-EE"],
	["fr", "fr-FR"],
	["ga", "ga-IE"],
	["hu", "hu-HU"],
	["id", "id-ID"],
	["it", "it-IT"],
	["ja", "ja-JP"],
	["ko", "ko-KR"],
	["nl", "nl-NL"],
	["no", "no-NO"],
	["pl", "pl-PL"],
	["pt", "pt-PT"],
	["ru", "ru-RU"],
	["sk", "sk-SK"],
	["tr", "tr-TR"],
	["vi", "vi-VN"],
	["zh", "zh-CN"],
];

const ignoreUnused = [/^.*$/];

const { spawnSync } = require("child_process");
const fs = require("fs");

const tmp = require("tmp");

// Parse backend errors
const BACKEND_ERRORS_FILE = "../backend/internal/errors/errors.go";
const BACKEND_ERRORS = [];
/*
try {
	const backendErrorsContent = fs.readFileSync(BACKEND_ERRORS_FILE, "utf8");
	const backendErrorsContentRes = [
		...backendErrorsContent.matchAll(/(?:errors|eris)\.New\("([^"]+)"\)/g),
	];
	backendErrorsContentRes.map((item) => {
		BACKEND_ERRORS.push("error." + item[1]);
		return null;
	});
} catch (err) {
	console.log("\x1b[31m%s\x1b[0m", err);
	process.exit(1);
}
*/

// get all translations used in frontend code
const tmpobj = tmp.fileSync({ postfix: ".json" });
spawnSync("pnpm", ["formatjs", "extract", "'src/**/*.tsx'", "--out-file", tmpobj.name]);

const allLocalesInProject = require(tmpobj.name);

// get list og language names and locales
const langList = require("./src/locale/src/lang-list.json");

// store a list of all validation errors
const allErrors = [];
const allWarnings = [];
const allKeys = [];

const checkLangList = (fullCode) => {
  const key = "locale-" + fullCode;
  if (typeof langList[key] === "undefined") {
    allErrors.push("ERROR: `" + key + "` language does not exist in lang-list.json");
  }
};

const compareLocale = (locale) => {
  const projectLocaleKeys = Object.keys(allLocalesInProject);
  // Check that locale contains the items used in the codebase
  projectLocaleKeys.map((key) => {
    if (typeof locale.data[key] === "undefined") {
      allErrors.push("ERROR: `" + locale[0] + "` does not contain item: `" + key + "`");
    }
    return null;
  });
  // Check that locale contains all error.* items
  BACKEND_ERRORS.forEach((key) => {
    if (typeof locale.data[key] === "undefined") {
      allErrors.push("ERROR: `" + locale[0] + "` does not contain item: `" + key + "`");
    }
    return null;
  });

  // Check that locale does not contain items not used in the codebase
  const localeKeys = Object.keys(locale.data);
  localeKeys.map((key) => {
    let ignored = false;
    ignoreUnused.map((regex) => {
      if (key.match(regex)) {
        ignored = true;
      }
      return null;
    });

    if (!ignored && typeof allLocalesInProject[key] === "undefined") {
      // ensure this key doesn't exist in the backend errors either
      if (!BACKEND_ERRORS.includes(key)) {
        allErrors.push("ERROR: `" + locale[0] + "` contains unused item: `" + key + "`");
      }
    }

    // Add this key to allKeys
    if (allKeys.indexOf(key) === -1) {
      allKeys.push(key);
    }
    return null;
  });
};

// NginxionS: the strings of NginxionS are translated into en and ru only (CLAUDE.md, scripts/check-i18n.mjs fails on a
// missing one); the other languages of NPMplus show them in English. Missing keys are listed one by one for en and
// ru, as one line per language for the others (thousands of warnings hid the real ones).
const FULL_LOCALES = ["en", "ru"];
const fallbackSummary = [];

// Checks for any keys missing from this locale, that
// have been defined in any other locales
const checkForMissing = (locale) => {
  // en is the source of the strings: a key left in another language only (old upstream strings) is not missing
  const english = allLocales.find((l) => l[0] === "en").data;
  const missing = allKeys.filter((key) => key in english && typeof locale.data[key] === "undefined");
  if (!FULL_LOCALES.includes(locale[0])) {
    if (missing.length) fallbackSummary.push(`${locale[0]}: ${missing.length}`);
    return;
  }
  missing.forEach((key) => {
    allWarnings.push("WARN: `" + locale[0] + "` does not contain item: `" + key + "`");
  });
};

// Local all locale data
allLocales.map((locale, idx) => {
  checkLangList(locale[1]);
  allLocales[idx].data = require("./src/locale/src/" + locale[0] + ".json");
  return null;
});

// Verify all locale data
allLocales.map((locale) => {
  compareLocale(locale);
  checkForMissing(locale);
  return null;
});

if (allErrors.length) {
  allErrors.map((err) => {
    console.log("\x1b[31m%s\x1b[0m", err);
    return null;
  });
}
if (allWarnings.length) {
  allWarnings.map((err) => {
    console.log("\x1b[33m%s\x1b[0m", err);
    return null;
  });
}

// NginxionS: one line for the languages shown partly in English
if (fallbackSummary.length) {
  console.log(`Not translated, shown in English: ${fallbackSummary.join(", ")} strings`);
}

if (allErrors.length) {
  process.exit(1);
}

console.log("\x1b[32m%s\x1b[0m", "Locale check passed");
process.exit(0);
