// A change of a text as in a code review: removed lines red, added green, unchanged ones folded to a few lines
// of context around each change, with line numbers of both sides.
import cn from "classnames";
import styles from "./CodeDiff.module.css";

export interface DiffLine {
	op: " " | "+" | "-";
	line: string;
}

const MAX_LINES = 3000;

/** line diff: common head and tail, then the longest common subsequence of the changed middle */
export const diffLines = (before: string, after: string): DiffLine[] => {
	const a = before.split("\n");
	const b = after.split("\n");
	let head = 0;
	while (head < a.length && head < b.length && a[head] === b[head]) head++;
	let tail = 0;
	while (tail < a.length - head && tail < b.length - head && a[a.length - 1 - tail] === b[b.length - 1 - tail])
		tail++;
	const ma = a.slice(head, a.length - tail);
	const mb = b.slice(head, b.length - tail);
	const out: DiffLine[] = a.slice(0, head).map((line) => ({ op: " ", line }));
	if (ma.length > MAX_LINES || mb.length > MAX_LINES) {
		out.push(...ma.map((line) => ({ op: "-" as const, line })), ...mb.map((line) => ({ op: "+" as const, line })));
	} else {
		const lcs = Array.from({ length: ma.length + 1 }, () => new Uint16Array(mb.length + 1));
		for (let i = ma.length - 1; i >= 0; i--) {
			for (let j = mb.length - 1; j >= 0; j--) {
				lcs[i][j] = ma[i] === mb[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
			}
		}
		let i = 0;
		let j = 0;
		while (i < ma.length && j < mb.length) {
			if (ma[i] === mb[j]) {
				out.push({ op: " ", line: ma[i++] });
				j++;
			} else if (lcs[i + 1][j] >= lcs[i][j + 1]) out.push({ op: "-", line: ma[i++] });
			else out.push({ op: "+", line: mb[j++] });
		}
		while (i < ma.length) out.push({ op: "-", line: ma[i++] });
		while (j < mb.length) out.push({ op: "+", line: mb[j++] });
	}
	out.push(...a.slice(a.length - tail).map((line) => ({ op: " " as const, line })));
	return out;
};

export function CodeDiff({ diff, context = 3 }: { diff: DiffLine[]; context?: number }) {
	const shown = diff.map((_, i) => diff.slice(Math.max(0, i - context), i + context + 1).some((d) => d.op !== " "));
	let left = 0;
	let right = 0;
	return (
		<div className={styles.diff}>
			{diff.map((d, i) => {
				if (d.op !== "+") left++;
				if (d.op !== "-") right++;
				if (!shown[i]) {
					return i > 0 && shown[i - 1] ? (
						<div key={i} className={styles.fold}>
							⋯
						</div>
					) : null;
				}
				return (
					<div key={i} className={cn(styles.line, d.op === "+" && styles.add, d.op === "-" && styles.del)}>
						<span className={styles.num}>{d.op === "+" ? "" : left}</span>
						<span className={styles.num}>{d.op === "-" ? "" : right}</span>
						<span className={styles.op}>{d.op}</span>
						<span className={styles.text}>{d.line}</span>
					</div>
				);
			})}
		</div>
	);
}
