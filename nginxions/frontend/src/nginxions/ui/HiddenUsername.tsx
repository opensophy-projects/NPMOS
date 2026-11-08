// Chrome warns about every form with a password field and no user name ("[DOM] Password forms should have
// (optionally hidden) username fields for accessibility"). The forms of NginxionS with keys and tokens have no user:
// a hidden, empty field answers the browser, and password managers leave the secret alone.
export function HiddenUsername({ value = "" }: { value?: string }) {
	return (
		<input
			type="text"
			name="username"
			autoComplete="username"
			value={value}
			readOnly
			hidden
			tabIndex={-1}
			aria-hidden="true"
		/>
	);
}
