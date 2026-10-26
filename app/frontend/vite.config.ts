import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import "vitest/config";
import { execFileSync } from "node:child_process";

const runLocaleScripts = () => {
	execFileSync("pnpm", ["formatjs", "compile-folder", "src/locale/src", "src/locale/lang"], {
		stdio: "inherit",
	});
	execFileSync("./src/locale/scripts/locale-sort.sh", {
		stdio: "inherit",
	});
};

// NPMOS: backend used by the dev server
const devApi = process.env.NPMOS_API || "https://127.0.0.1:81";

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
	},
	server: {
		host: true,
		port: 5173,
		strictPort: true,
		allowedHosts: true,
		// NPMOS: dev server talks to a running backend (deploy/compose.dev.yaml), NPMOS_API overrides it.
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
	},
	assetsInclude: ["**/*.md", "**/*.png", "**/*.svg"],
});
