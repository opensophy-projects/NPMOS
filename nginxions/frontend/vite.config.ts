import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import "vitest/config";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const runLocaleScripts = () => {
	execFileSync("pnpm", ["formatjs", "compile-folder", "src/locale/src", "src/locale/lang"], {
		stdio: "inherit",
	});
	execFileSync("./src/locale/scripts/locale-sort.sh", {
		stdio: "inherit",
	});
};

// NginxionS: backend used by the dev server
const devApi = process.env.NGINXIONS_API || "https://127.0.0.1:81";

// https://vitejs.dev/config/
export default defineConfig({
	plugins: [
		{
			name: "run-on-start",
			configureServer(_server) {
				runLocaleScripts();
			},
		},
		{
			name: "trigger-on-reload",
			configureServer(server) {
				server.watcher.on("change", (file) => {
					if (file.includes("locale/src")) {
						console.log(`File changed: ${file}, running locale scripts...`);
						runLocaleScripts();
					}
				});
			},
		},
		react(),
	],
	resolve: {
		tsconfigPaths: true,
		// NginxionS: the code editor with the grammars the interface shows only (src/nginxions/components/CodeEditor.tsx);
		// the editor itself imports the package without its grammars (/nohighlight)
		alias: [
			{
				find: /^@uiw\/react-textarea-code-editor$/,
				replacement: fileURLToPath(new URL("./src/nginxions/components/CodeEditor.tsx", import.meta.url)),
			},
		],
	},
	server: {
		host: true,
		port: 5173,
		strictPort: true,
		allowedHosts: true,
		// NginxionS: dev server talks to a running backend (deploy/compose.dev.yaml), NGINXIONS_API overrides it.
		// Origin is rewritten too: the backend rejects requests whose Origin differs from its own host.
		proxy: Object.fromEntries(
			["/api", "/images/gravatar"].map((path) => [
				path,
				{ target: devApi, secure: false, changeOrigin: true, headers: { origin: new URL(devApi).origin } },
			]),
		),
	},
	test: {
		environment: "happy-dom",
		setupFiles: ["./vitest-setup.js"],
		// NginxionS: Node 25+ has a localStorage of its own (undefined without --localstorage-file) that hides the one of
		// happy-dom in the test workers: tests failed on Node 26 LTS with "reading 'getItem'" of undefined
		execArgv: ["--no-experimental-webstorage"],
	},
	assetsInclude: ["**/*.md", "**/*.png", "**/*.svg"],
});
