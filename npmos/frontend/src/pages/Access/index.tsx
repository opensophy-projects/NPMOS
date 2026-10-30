import { HasPermission } from "src/components";
import { ACCESS_LISTS, VIEW } from "src/modules/Permissions";
// NPMOS: what an access list is for, above the table
import { AccessIntro } from "src/npmos/pages/Access/Intro";
import TableWrapper from "./TableWrapper";

const Access = () => {
	return (
		<HasPermission section={ACCESS_LISTS} permission={VIEW} pageLoading loadingNoLogo>
			<AccessIntro />
			<TableWrapper />
		</HasPermission>
	);
};

export default Access;
