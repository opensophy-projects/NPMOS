// NPMOS: toasts are notice blocks of the opensophy design (src/npmos/ui/Admonition.tsx, phase 2)
import { Admonition } from "src/npmos/ui/Admonition";

function Msg({ data }: any) {
	return (
		<div role="alert" aria-live="assertive" aria-atomic="true">
			<Admonition compact variant={data.type === "error" ? "alert" : "success"} title={data.title}>
				{data.message}
			</Admonition>
		</div>
	);
}
export { Msg };
