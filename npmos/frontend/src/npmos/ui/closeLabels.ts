// The close buttons of react-bootstrap (modals, alerts) carry aria-label="Close" in English and the
// upstream dialogs do not pass a label. Translate them where they appear, instead of editing every dialog.
import { useEffect } from "react";
import { useLocaleState } from "src/context";
import { intl } from "src/locale";

const SELECTOR = "button.btn-close";

export function useCloseLabels() {
	const { locale } = useLocaleState();
	// biome-ignore lint/correctness/useExhaustiveDependencies: the label is read again when the language changes
	useEffect(() => {
		const label = intl.formatMessage({ id: "npmos.common.close" });
		const fix = (root: ParentNode) => {
			for (const button of root.querySelectorAll<HTMLButtonElement>(SELECTOR)) {
				if (button.getAttribute("aria-label") !== label) button.setAttribute("aria-label", label);
			}
		};
		fix(document);
		const observer = new MutationObserver((records) => {
			for (const record of records) {
				for (const node of record.addedNodes) {
					if (node instanceof Element) fix(node.matches(SELECTOR) ? (node.parentNode ?? node) : node);
				}
			}
		});
		observer.observe(document.body, { childList: true, subtree: true });
		return () => observer.disconnect();
	}, [locale]);
}
