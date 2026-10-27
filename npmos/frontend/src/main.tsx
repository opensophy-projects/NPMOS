import React from "react";
import ReactDOM from "react-dom/client";
import App from "src/App.tsx";

import "@tabler/core/dist/css/tabler.min.css";
import "@tabler/core/dist/js/tabler.min.js";
import "./App.css";
// NPMOS: opensophy design tokens over Tabler (phase 2)
import "./npmos/ui/tokens.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
	<React.StrictMode>
		<App />
	</React.StrictMode>,
);
