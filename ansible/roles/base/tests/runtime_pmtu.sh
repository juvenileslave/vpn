#!/usr/bin/env bash
# Invoked only by the guarded disposable runtime; real router-generated PMTU.
set -euo pipefail
[[ ${VPN_BASE_DISPOSABLE_GUEST:-} == yes && ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && $EUID == 0 ]] \
  || { echo 'Disposable GitHub-hosted guest required.' >&2; exit 2; }
WORK=$1 PORT=$2 SERVICE=$3
capture_pid=
old_probing=$(sysctl -n net.ipv4.tcp_mtu_probing)
cleanup() {
  if [[ -n $capture_pid ]]; then kill "$capture_pid" 2>/dev/null || true; wait "$capture_pid" 2>/dev/null || true; fi
  sysctl -qw "net.ipv4.tcp_mtu_probing=$old_probing"
  ip route del 203.0.113.0/24 via 192.0.2.2 2>/dev/null || true
  ip -6 route del 2001:db8:201::/64 via 2001:db8:200::2 2>/dev/null || true
  ip netns delete pmtu-client 2>/dev/null || true
  ip netns delete pmtu-router 2>/dev/null || true
  ip link delete v-pmtu 2>/dev/null || true
}
trap cleanup EXIT
diagnose() {
  printf '[DEBUG-pmtu] failing line %s\n' "$1" >&2
  if [[ -n $capture_pid ]]; then
    kill -INT "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
    capture_pid=
  fi
  ip -n pmtu-client route get 192.0.2.1 >&2 || true
  ip -n pmtu-client -6 route get 2001:db8:200::1 >&2 || true
  ip -n pmtu-router route get 203.0.113.2 >&2 || true
  ip -n pmtu-router -6 route get 2001:db8:201::2 >&2 || true
  ip route get 203.0.113.2 >&2 || true
  ip -6 route get 2001:db8:201::2 >&2 || true
  ip -n pmtu-client neigh show >&2 || true
  ip -n pmtu-router neigh show >&2 || true
  ip neigh show dev v-pmtu >&2 || true
  ip -6 addr show dev v-pmtu >&2 || true
  nft list table inet vpn_base >&2 || true
  [[ ! -e $WORK/nd-pmtu.log ]] || cat "$WORK/nd-pmtu.log" >&2
}
trap 'diagnose "$LINENO"' ERR
ip netns add pmtu-router
ip netns add pmtu-client
ip link add v-pmtu type veth peer name upstream netns pmtu-router
ip -n pmtu-router link add downstream type veth peer name eth0 netns pmtu-client
ip link set v-pmtu up
ip addr add 192.0.2.1/24 dev v-pmtu
ip -6 addr add 2001:db8:200::1/64 dev v-pmtu nodad
for ns in pmtu-router pmtu-client; do ip -n "$ns" link set lo up; done
ip -n pmtu-router link set upstream up
ip -n pmtu-router link set downstream mtu 1280 up
# The client advertises MSS for 1500, while only the router's outbound link is
# 1280. SYN negotiation cannot avoid the later ICMP-driven PMTU transition.
ip -n pmtu-client link set eth0 mtu 1500 up
ip -n pmtu-router addr add 192.0.2.2/24 dev upstream
ip -n pmtu-router -6 addr add 2001:db8:200::2/64 dev upstream nodad
ip -n pmtu-router addr add 203.0.113.1/24 dev downstream
ip -n pmtu-router -6 addr add 2001:db8:201::1/64 dev downstream nodad
ip -n pmtu-client addr add 203.0.113.2/24 dev eth0
ip -n pmtu-client -6 addr add 2001:db8:201::2/64 dev eth0 nodad
ip -n pmtu-client route add default via 203.0.113.1
ip -n pmtu-client -6 route add default via 2001:db8:201::1
ip route add 203.0.113.0/24 via 192.0.2.2
ip -6 route add 2001:db8:201::/64 via 2001:db8:200::2
ip netns exec pmtu-router sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
# Disable black-hole fallback on the HOST: transfer must depend on ICMP PMTU.
# The original setting is restored by the exit trap; forwarding is never changed.
sysctl -qw net.ipv4.tcp_mtu_probing=0
ip netns exec pmtu-client ping -c1 -W2 192.0.2.1
tcpdump -i v-pmtu -nn -v 'icmp6' > "$WORK/nd-pmtu.log" 2>&1 &
capture_pid=$!
sleep 1
kill -0 "$capture_pid"
ip netns exec pmtu-client ping -c1 -W2 2001:db8:200::1
kill -INT "$capture_pid"
wait "$capture_pid"
capture_pid=
# Disable segmentation offload on the test veths so tcpdump and the router see
# real MTU-sized packets, not oversized local GSO aggregates.
ethtool -K v-pmtu tso off gso off gro off >/dev/null
ip netns exec pmtu-router ethtool -K upstream tso off gso off gro off >/dev/null
ip netns exec pmtu-router ethtool -K downstream tso off gso off gro off >/dev/null
tcpdump -i v-pmtu -nn -U -w "$WORK/pmtu.pcap" 'icmp or icmp6' > "$WORK/pmtu-capture.log" 2>&1 &
capture_pid=$!
sleep 1
kill -0 "$capture_pid"
ip netns exec pmtu-client python3 "$SERVICE" get 192.0.2.1 "$PORT"
ip netns exec pmtu-client python3 "$SERVICE" get 2001:db8:200::1 "$PORT"
kill -INT "$capture_pid"
wait "$capture_pid"
capture_pid=
tcpdump -nr "$WORK/pmtu.pcap" 'icmp[0] == 3 and icmp[1] == 4' 2>/dev/null > "$WORK/pmtu-v4.txt"
tcpdump -nr "$WORK/pmtu.pcap" 'icmp6 and ip6[40] == 2' 2>/dev/null > "$WORK/pmtu-v6.txt"
[[ -s $WORK/pmtu-v4.txt && -s $WORK/pmtu-v6.txt ]] \
  || { echo 'Missing actual fragmentation-needed/packet-too-big packets.' >&2; exit 1; }
echo 'OK: IPv4/IPv6 1 MiB hash-checked transfers depend on observed router PMTU errors.'
