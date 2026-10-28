// Theme toggle, language and user menu of the sidebar.
import { IconLock, IconLogout, IconMoon, IconSelector, IconShieldLock, IconSun, IconUser } from "@tabler/icons-react";
import cn from "classnames";
import { useAuthState, useLocaleState } from "src/context";
import { useTheme, useUser } from "src/hooks";
import { changeLocale, intl, localeOptions, T } from "src/locale";
import { showChangePasswordModal, showTwoFactorModal, showUserModal } from "src/modals";
import { Dropdown } from "./Dropdown";
import { useRbacMe } from "../rbac/hooks";
import { roleName } from "../rbac/labels";
import styles from "./Shell.module.css";

/** logo and name as on opensophy.com: the sidebar, the login and setup pages */
export function Brand() {
	return (
		<span className={styles.brandMark}>
			<img src="/images/logo-no-text.svg" alt="" className={styles.brandLogo} />
			<span className={styles.brandName}>npmos</span>
		</span>
	);
}

export function ThemeToggle() {
	const { theme, toggleTheme } = useTheme();
	const dark = theme === "dark";
	return (
		<span className={styles.toggleWrap}>
			<button
				type="button"
				className={styles.toggle}
				onClick={toggleTheme}
				aria-label={intl.formatMessage({ id: dark ? "npmos.nav.theme-light" : "npmos.nav.theme-dark" })}
				title={intl.formatMessage({ id: dark ? "npmos.nav.theme-light" : "npmos.nav.theme-dark" })}
			>
				<span className={cn(styles.icon, !dark && styles.iconOn)}>
					<IconSun size={16} />
				</span>
				<span className={cn(styles.icon, dark && styles.iconOn)}>
					<IconMoon size={16} />
				</span>
			</button>
		</span>
	);
}

/** Switches the language in place (LocaleProvider re-renders the app, no page reload). */
export function LocaleSwitch() {
	const { locale, setLocale } = useLocaleState();
	const current = (locale || "en").slice(0, 2);
	return (
		<span className={styles.toggleWrap}>
			<Dropdown
				inline
				up
				ariaLabel={intl.formatMessage({ id: "npmos.nav.language" })}
				triggerClassName={styles.toggle}
				menuClassName={styles.menuCompact}
				trigger={current.toUpperCase()}
				items={localeOptions.map((option) => {
					const code = option[0] as string;
					return {
						key: code,
						label: <T id={`locale-${option[1]}`} />,
						active: code === current,
						onSelect: () => {
							changeLocale(code);
							setLocale(code);
						},
					};
				})}
			/>
		</span>
	);
}

export function UserMenu() {
	const { data: me } = useUser("me");
	const { logout } = useAuthState();
	const { data: rbac } = useRbacMe();
	// the first role of the user (Administrator first), "no role" without any
	const role = rbac?.roles[0];
	return (
		<Dropdown
			ariaLabel={intl.formatMessage({ id: "npmos.nav.user-menu" })}
			trigger={
				<>
					<span className={styles.triggerLabel}>
						<span
							className={styles.avatar}
							style={{ backgroundImage: `url(${me?.avatar || "/images/default-avatar.jpg"})` }}
						/>
						{me?.nickname || me?.name}
						<span>·</span>
						{role ? roleName(role) : <T id="npmos.rbac.no-roles" />}
					</span>
					<IconSelector size={16} style={{ flex: "none" }} />
				</>
			}
			items={[
				{
					key: "profile",
					icon: <IconUser size={16} />,
					label: <T id="user.edit-profile" />,
					onSelect: () => showUserModal("me"),
				},
				{
					key: "password",
					icon: <IconLock size={16} />,
					label: <T id="user.change-password" />,
					onSelect: () => showChangePasswordModal("me"),
				},
				{
					key: "2fa",
					icon: <IconShieldLock size={16} />,
					label: <T id="user.two-factor" />,
					onSelect: () => showTwoFactorModal("me"),
				},
				{
					key: "logout",
					divider: true,
					icon: <IconLogout size={16} />,
					label: <T id="user.logout" />,
					onSelect: logout,
				},
			]}
		/>
	);
}
