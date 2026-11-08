import { useQueryClient } from "@tanstack/react-query";
import { Field, Form, Formik } from "formik";
import { useState } from "react";
import { Alert } from "react-bootstrap";
import { createUser } from "src/api/backend";
import { Button } from "src/components";
import { useAuthState } from "src/context";
import { intl, T } from "src/locale";
import { validateEmail, validateString } from "src/modules/Validations";
// NPMOS: centred panel with brand, theme and language of the opensophy shell (phase 2)
import { AuthLayout } from "src/npmos/ui/AuthLayout";

interface Payload {
	name: string;
	email: string;
	password: string;
}

export default function Setup() {
	const queryClient = useQueryClient();
	const { login } = useAuthState();
	const [errorMsg, setErrorMsg] = useState<string | null>(null);

	const onSubmit = async (values: Payload, { setSubmitting }: any) => {
		setErrorMsg(null);

		// Set a nickname, which is the first word of the name
		const nickname = values.name.split(" ")[0];

		const { password, ...payload } = {
			...values,
			...{
				nickname,
				auth: {
					type: "password",
					secret: values.password,
				},
			},
		};

		try {
			const user = await createUser(payload);
			if (user?.id) {
				try {
					await login(user.email, password);
					// Trigger a Health change
					await queryClient.refetchQueries({ queryKey: ["health"] });
					// window.location.reload();
				} catch (err: any) {
					setErrorMsg(err.message);
				}
			} else {
				setErrorMsg("cannot_create_user");
			}
		} catch (err: any) {
			setErrorMsg(err.message);
		}
		setSubmitting(false);
	};

	// NPMOS: the registration of the first administrator in the look of the login page (labels above the fields,
	// one card body); was a "Welcome!" header with floating labels.
	const field = (name: keyof Payload, label: string, validate: any, input: Record<string, any>) => (
		<div className="mb-3">
			<Field name={name} validate={validate}>
				{({ field, form }: any) => (
					<label className="form-label">
						<T id={label} />
						<input
							{...field}
							{...input}
							required
							className={`form-control ${form.errors[name] && form.touched[name] ? " is-invalid" : ""}`}
							placeholder={intl.formatMessage({ id: label })}
						/>
						<div className="invalid-feedback">{form.errors[name]}</div>
					</label>
				)}
			</Field>
		</div>
	);

	return (
		<AuthLayout>
			<div className="card card-md">
				<div className="card-body">
					<h2 className="h2 text-center mb-2">
						<T id="npmos.setup.title" />
					</h2>
					<p className="text-secondary text-center mb-4">
						<T id="npmos.setup.hint" />
					</p>
					<Alert variant="danger" show={!!errorMsg} onClose={() => setErrorMsg(null)} dismissible>
						{errorMsg}
					</Alert>
					<Formik initialValues={{ name: "", email: "", password: "" } as any} onSubmit={onSubmit}>
						{({ isSubmitting }) => (
							<Form>
								{field("name", "user.full-name", validateString(1, 50), { autoComplete: "name" })}
								{field("email", "email-address", validateEmail(), {
									type: "email",
									autoComplete: "username",
								})}
								{field("password", "password", validateString(8, 100), {
									type: "password",
									autoComplete: "new-password",
									maxLength: 100,
								})}
								<div className="form-footer">
									<Button type="submit" fullWidth actionType="primary" isLoading={isSubmitting}>
										<T id="npmos.setup.submit" />
									</Button>
								</div>
							</Form>
						)}
					</Formik>
				</div>
			</div>
		</AuthLayout>
	);
}
