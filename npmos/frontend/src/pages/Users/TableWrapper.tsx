// NPMOS: hardcoded strings moved to the locale (en, ru)
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import Alert from "react-bootstrap/Alert";
import { deleteUser, toggleUser } from "src/api/backend";
import { Button, LoadingPage } from "src/components";
import { useAuthState } from "src/context";
import { useUser, useUsers } from "src/hooks";
import { intl, T } from "src/locale";
import { showDeleteConfirmModal, showSetPasswordModal, showUserModal } from "src/modals";
// NPMOS: permissions of a user are its roles (phase 3)
import { showUserRolesModal } from "src/npmos/rbac/UserRolesModal";
import { showError, showObjectSuccess } from "src/notifications";
import Table from "./Table";
// NPMOS: one look of search fields (src/npmos/ui/SearchField)
import { SearchField } from "src/npmos/ui/SearchField";

export default function TableWrapper() {
	const queryClient = useQueryClient();
	const { loginAs } = useAuthState();
	const [search, setSearch] = useState("");
	const [text, setText] = useState("");
	const { isFetching, isLoading, isError, error, data } = useUsers(["permissions"]);
	const { data: currentUser } = useUser("me");

	if (isLoading) {
		return <LoadingPage />;
	}

	if (isError) {
		return <Alert variant="danger">{error?.message || <T id="npmos.common.unknown-error" />}</Alert>;
	}

	const handleLoginAs = async (id: number) => {
		try {
			await loginAs(id);
		} catch (err) {
			if (err instanceof Error) {
				showError(err.message);
			}
		}
	};

	const handleDelete = async (id: number) => {
		await deleteUser(id);
		showObjectSuccess("user", "deleted");
	};

	const handleDisableToggle = async (id: number, enabled: boolean) => {
		await toggleUser(id, enabled);
		queryClient.invalidateQueries({ queryKey: ["users"] });
		queryClient.invalidateQueries({ queryKey: ["user", id] });
		showObjectSuccess("user", enabled ? "enabled" : "disabled");
	};

	let filtered = null;
	if (search && data) {
		filtered = data?.filter((item) => {
			return (
				item.name.toLowerCase().includes(search) ||
				item.nickname.toLowerCase().includes(search) ||
				item.email.toLowerCase().includes(search)
			);
		});
	} else if (search !== "") {
		// this can happen if someone deletes the last item while searching
		setSearch("");
	}

	return (
		<div className="card mt-4">
			<div className="card-status-top bg-orange" />
			<div className="card-table">
				<div className="card-header">
					<div className="row w-full">
						<div className="col">
							<h2 className="mt-1 mb-0">
								<T id="users" />
							</h2>
						</div>
						{data?.length ? (
							<div className="col-md-auto col-sm-12">
								<div className="ms-auto d-flex flex-wrap btn-list">
									<SearchField
										// NPMOS: the search field of NPMOS tables, with a hint of what it covers
										variant="inset"
										value={text}
										onChange={(value) => {
											setText(value);
											setSearch(value.toLowerCase().trim());
										}}
										placeholder={intl.formatMessage({ id: "npmos.users.search" })}
									/>

									<Button size="sm" className="btn-orange" onClick={() => showUserModal("new")}>
										<T id="object.add" tData={{ object: "user" }} />
									</Button>
								</div>
							</div>
						) : null}
					</div>
				</div>
				<Table
					data={filtered ?? data ?? []}
					isFiltered={!!search}
					isFetching={isFetching}
					currentUserId={currentUser?.id}
					onEditUser={(id: number) => showUserModal(id)}
					onEditPermissions={(id: number) =>
						showUserRolesModal(id, (data ?? []).find((u) => u.id === id)?.name ?? "")
					}
					onSetPassword={(id: number) => showSetPasswordModal(id)}
					onDeleteUser={(id: number) =>
						showDeleteConfirmModal({
							title: <T id="object.delete" tData={{ object: "user" }} />,
							onConfirm: () => handleDelete(id),
							invalidations: [["users"], ["user", id]],
							children: <T id="object.delete.content" tData={{ object: "user" }} />,
						})
					}
					onDisableToggle={handleDisableToggle}
					onNewUser={() => showUserModal("new")}
					onLoginAs={handleLoginAs}
				/>
			</div>
		</div>
	);
}
