"""Role-local ACL validation: never echo input values or secrets."""
import ipaddress


def acl_valid(sources, rules, port, public, ssh, placement, source, address):
    try:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 or port == ssh:
            return False
        if not isinstance(sources, list) or not sources:
            return False
        nets = [ipaddress.ip_network(s, strict=True) for s in sources]
        if len(set(nets)) != len(nets):
            return False
        loopbacks = {ipaddress.ip_network('127.0.0.1/32'), ipaddress.ip_network('::1/128')}
        for net in nets:
            if net in loopbacks:
                continue
            if net.prefixlen == 0 or net.is_multicast or net.is_unspecified or net.is_loopback or net.is_link_local:
                return False
            if net.prefixlen < (24 if net.version == 4 else 64):
                return False
        src = ipaddress.ip_address(source)
        dst = ipaddress.ip_address(address)
        if src.version != dst.version or not any(src in n for n in nets if n.version == src.version):
            return False
        if placement == 'exit':
            if src.is_loopback != dst.is_loopback or not src.is_private or not dst.is_private:
                return False
            if not src.is_loopback and any(not n.is_private for n in nets):
                return False
        if placement == 'dedicated' and (src.is_loopback or dst.is_loopback or not dst.is_private):
            return False
        if any(r.get('port') == port for r in public):
            return False
        matches = [r for r in rules if r.get('port') == port]
        return len(matches) == 1 and matches[0].get('proto') == 'tcp' and set(matches[0].get('source_cidrs', [])) == set(sources)
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


class FilterModule:
    def filters(self):
        return {'remnawave_node_acl_valid': acl_valid}
