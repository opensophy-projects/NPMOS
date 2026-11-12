// NginxionS: the code editor of the interface (@uiw/react-textarea-code-editor) with the grammars it shows only
// (nginx, YAML, JSON, Bash, PHP), not the ~300 of Prism the package bundles: a smaller bundle, and no grammar text
// like "eval(" that scanners take for code (DAST: ZAP 10110). vite.config.ts points the imports of the package here.
import Editor, { type TextareaCodeEditorProps } from "@uiw/react-textarea-code-editor/nohighlight";
import { forwardRef } from "react";
import rehypePrismGenerator from "rehype-prism-plus/generator";
import { refractor } from "refractor/lib/core.js";
import bash from "refractor/lang/bash.js";
import json from "refractor/lang/json.js";
import nginx from "refractor/lang/nginx.js";
import php from "refractor/lang/php.js";
import yaml from "refractor/lang/yaml.js";

for (const lang of [bash, json, nginx, php, yaml]) refractor.register(lang);
const rehypePrism = rehypePrismGenerator(refractor);

const CodeEditor = forwardRef<HTMLTextAreaElement, TextareaCodeEditorProps>((props, ref) => (
	<Editor rehypePlugins={[[rehypePrism, { ignoreMissing: true }]]} {...props} ref={ref} />
));
CodeEditor.displayName = "CodeEditor";

export default CodeEditor;
export * from "@uiw/react-textarea-code-editor/nohighlight";
