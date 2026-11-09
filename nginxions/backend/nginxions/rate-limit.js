// A limit of requests per client address for routes that hand out secrets or act as another user: the download of a
// certificate with its private key, the login as another user. Both need the token of an allowed user already; the
// limit stops a stolen or scripted session from pulling them in bulk. The login itself has its own (routes/tokens.js).
import { rateLimit } from "express-rate-limit";

export const sensitiveLimiter = rateLimit({
	windowMs: 60 * 1000,
	limit: 30,
	message: { error: { message: "Too many requests, please try again later." } },
	standardHeaders: "draft-8",
	legacyHeaders: false,
	ipv6Subnet: 48,
	validate: { trustProxy: false },
});
