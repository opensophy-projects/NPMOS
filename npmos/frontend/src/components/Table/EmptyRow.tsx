// NPMOS: hardcoded strings moved to the locale (en, ru)
import type { Table as ReactTable } from "@tanstack/react-table";
import { T } from "src/locale";

interface Props {
	tableInstance: ReactTable<any>;
}
function EmptyRow({ tableInstance }: Props) {
	return (
		<tr>
			<td colSpan={tableInstance.getVisibleFlatColumns().length}>
				<p className="text-center">
					<T id="npmos.common.no-items" />
				</p>
			</td>
		</tr>
	);
}

export { EmptyRow };
