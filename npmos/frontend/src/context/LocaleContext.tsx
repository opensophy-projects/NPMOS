import { createContext, Fragment, type ReactNode, useContext, useState } from "react";
import { getLocale } from "src/locale";

// Context
export interface LocaleContextType {
	setLocale: (locale: string) => void;
	locale?: string;
}

const initalValue = null;
const LocaleContext = createContext<LocaleContextType | null>(initalValue);

// Provider
interface Props {
	children?: ReactNode;
}
function LocaleProvider({ children }: Props) {
	const [locale, setLocaleValue] = useState(getLocale());

	const setLocale = async (locale: string) => {
		setLocaleValue(locale);
	};

	const value = { locale, setLocale };

	// NPMOS: the tree is rendered again with the new messages, the language changes without a reload
	return (
		<LocaleContext.Provider value={value}>
			<Fragment key={locale}>{children}</Fragment>
		</LocaleContext.Provider>
	);
}

function useLocaleState() {
	const context = useContext(LocaleContext);
	if (!context) {
		throw new Error("useLocaleState must be used within a LocaleProvider");
	}
	return context;
}

export { LocaleProvider, useLocaleState };
export default LocaleContext;
