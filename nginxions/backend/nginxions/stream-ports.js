// Streams: one incoming port (or range) per protocol. nginx listens on the ports of streams with "reuseport", so
// "nginx -t" accepted a second stream on a busy port and the kernel shared the connections between the two: the
// second stream answered at random, and disabling it changed nothing. The ports of NginxionS itself (the hosts and the
// panel) were taken the same way.
import errs from "../lib/error.js";

/** "2222" or "1000-2000" → [from, to] */
export const portRange = (value) => {
	const [a, b = a] = String(value).split("-").map(Number);
	return [Math.min(a, b), Math.max(a, b)];
};

const overlaps = ([a1, b1], [a2, b2]) => a1 <= b2 && a2 <= b1;

/** the ports nginx listens on for the hosts and the panel */
export const reservedPorts = (env = process.env) => ({
	tcp: [Number(env.HTTP_PORT || 80), Number(env.HTTPS_PORT || 443), 81],
	udp: env.DISABLE_H3_QUIC === "true" ? [] : [Number(env.HTTPS_PORT || 443)],
});

/**
 * Why the stream cannot listen on its port, or null
 * @param {{id?, incoming_port, tcp_forwarding, udp_forwarding}} stream
 * @param {Array<{id, incoming_port, tcp_forwarding, udp_forwarding}>} others  enabled streams
 * @param {{tcp: number[], udp: number[]}} reserved
 */
export const portConflict = (stream, others, reserved) => {
	const range = portRange(stream.incoming_port);
	for (const proto of ["tcp", "udp"]) {
		if (!stream[`${proto}_forwarding`]) continue;
		const own = reserved[proto].find((port) => overlaps(range, [port, port]));
		if (own !== undefined)
			return `Port ${own}/${proto.toUpperCase()} is used by NginxionS itself (hosts and the panel)`;
		const other = others.find(
			(o) =>
				Number(o.id) !== Number(stream.id) &&
				o[`${proto}_forwarding`] &&
				overlaps(range, portRange(o.incoming_port)),
		);
		if (other) {
			return `Port ${stream.incoming_port}/${proto.toUpperCase()} is already used by the stream on port ${other.incoming_port}`;
		}
	}
	return null;
};

/**
 * @param {Object} stream
 * @param {() => Promise<Array>} enabledStreams  the enabled streams that are not deleted
 */
export const assertStreamPortFree = async (stream, enabledStreams) => {
	const conflict = portConflict(stream, await enabledStreams(), reservedPorts());
	if (conflict) throw new errs.ValidationError(conflict);
};
