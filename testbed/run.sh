#!/usr/bin/env bash
# Runs attack-lab scenarios in the Docker testbed and checks each defense.
#
#   testbed/run.sh            build, then run every scenario
#   testbed/run.sh poison     run one scenario (see the list at the bottom)
#   testbed/run.sh down       remove the testbed
#
# Everything runs on an internal Docker network with no internet route. Logs
# from the last run of each scenario are left under testbed/logs/.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
logs="$here/logs"
mkdir -p "$logs"

SEED=10.88.1.10 VICTIM=10.88.1.20 DHT=10.88.1.30
ALICE=10.88.1.40 BOB=10.88.1.41 CAROL=10.88.1.42 ATTACKER=10.88.66.10

dc() { docker compose -f "$here/docker-compose.yml" "$@"; }
# x runs a command in a container and waits; bg starts it in the background.
x() { local svc=$1; shift; dc exec -T "$svc" sh -c "$*"; }
bg() { local svc=$1; shift; dc exec -d -T "$svc" sh -c "$*"; }

failures=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; failures=$((failures + 1)); }
check() { # check "description" command...
	local what=$1; shift
	if "$@"; then pass "$what"; else fail "$what"; fi
}
save() { x "$1" "cat $2 2>/dev/null" > "$logs/$3"; }

up() {
	dc up -d --build --wait >/dev/null || { echo "testbed failed to start"; exit 1; }
}

# reset stops every process from the last scenario and clears its state.
reset() {
	for s in seed victim dht alice bob carol attacker; do
		# Exact names: a pattern would also match this shell's own command line.
		x "$s" "pkill -x beacon; pkill -x attacker; pkill -x tail; rm -rf /tmp/*; true" >/dev/null 2>&1
	done
	x seed "rm -rf /lab/* && mkdir -p /lab/data"
}

# setup makes an 8 MB file and its torrent, shared by the seed.
setup() {
	reset
	x seed "head -c 8000000 /dev/urandom > /lab/data/lab.bin && beacon create -o /lab/lab.torrent /lab/data/lab.bin" \
		> "$logs/create.log" 2>&1
	MAGNET=$(grep '^magnet' "$logs/create.log" | awk '{print $2}')
	IH=$(grep '^info-hash' "$logs/create.log" | awk '{print $2}')
}

seed_plain() {
	bg seed "beacon seed -dir /lab/data -no-dht -no-lpd -port 6881 /lab/lab.torrent > /tmp/seed.log 2>&1"
	sleep 1
}

same_file() { x victim "cmp -s /tmp/dl/lab.bin /lab/data/lab.bin"; }
logged() { grep -q "$2" "$logs/$1"; } # logged file pattern

scenario_poison() {
	echo "Piece poisoning: an attacker seeds corrupted pieces"
	setup
	seed_plain
	bg attacker "attacker poison -torrent /lab/lab.torrent -listen :6881 > /tmp/attack.log 2>&1"
	sleep 1
	# The attacker is listed first, so the victim starts with it.
	x victim "timeout 120 beacon get -v -no-dht -no-lpd -o /tmp/dl -peer $ATTACKER:6881 -peer $SEED:6881 /lab/lab.torrent > /tmp/victim.log 2>&1"
	save victim /tmp/victim.log poison-victim.log
	save attacker /tmp/attack.log poison-attacker.log
	check "victim detected corrupt pieces by hash" logged poison-victim.log "piece failed hash check"
	check "victim banned the attacker" logged poison-victim.log "banning peer.*peer=$ATTACKER"
	check "download completed and matches the original" same_file
}

scenario_flood() {
	echo "Connection and message flood against a seeder"
	setup
	seed_plain
	bg attacker "attacker flood -torrent /lab/lab.torrent -target $SEED:6881 -conns 32 -msgs 3000 > /tmp/attack.log 2>&1"
	sleep 1
	x victim "timeout 120 beacon get -no-dht -no-lpd -o /tmp/dl -peer $SEED:6881 /lab/lab.torrent > /tmp/victim.log 2>&1"
	sleep 3
	save seed /tmp/seed.log flood-seed.log
	save attacker /tmp/attack.log flood-attacker.log
	check "seeder banned the flooding address" logged flood-seed.log "banning peer.*peer=$ATTACKER"
	check "most flood connections were refused or cut off" \
		grep -Eq 'refused=([3-9]|[1-9][0-9])|cut off"?=([3-9]|[1-9][0-9])' "$logs/flood-attacker.log"
	check "an honest peer downloaded during the flood" same_file
}

scenario_badmeta() {
	echo "Bad metadata for a magnet link (wrong data, and oversized)"
	setup
	seed_plain
	bg attacker "attacker badmeta -torrent /lab/lab.torrent -listen :6881 > /tmp/attack.log 2>&1"
	bg attacker "attacker badmeta -oversize -torrent /lab/lab.torrent -listen :6882 > /tmp/attack2.log 2>&1"
	sleep 1
	x victim "timeout 120 beacon get -v -no-dht -no-lpd -o /tmp/dl -peer $ATTACKER:6881 -peer $ATTACKER:6882 -peer $SEED:6881 '$MAGNET' > /tmp/victim.log 2>&1"
	save victim /tmp/victim.log badmeta-victim.log
	save attacker /tmp/attack.log badmeta-attacker.log
	check "victim rejected metadata from the attacker" logged badmeta-victim.log "metadata fetch failed.*$ATTACKER"
	check "download completed with the real metadata" same_file
}

scenario_sybil() {
	echo "DHT Sybil and eclipse: 32 fake nodes in one /24 surround every lookup"
	setup
	bg dht "beacon dht -port 6881 > /tmp/dht.log 2>&1"
	sleep 1
	bg seed "beacon seed -dir /lab/data -no-lpd -allow-private -dht-bootstrap $DHT:6881 -port 6881 /lab/lab.torrent > /tmp/seed.log 2>&1"
	bg attacker "attacker sybil -ip $ATTACKER -port 7000 -nodes 32 > /tmp/attack.log 2>&1"
	sleep 8 # the seed bootstraps and announces itself to the DHT
	# The victim knows two Sybils and one honest node, and has nothing else:
	# no trackers, no peers in the magnet.
	x victim "timeout 150 beacon get -v -no-lpd -allow-private -dht-bootstrap $ATTACKER:7000 -dht-bootstrap $ATTACKER:7001 -dht-bootstrap $DHT:6881 -o /tmp/dl 'magnet:?xt=urn:btih:$IH' > /tmp/victim.log 2>&1"
	x attacker "pkill -INT -x attacker"
	sleep 1
	save victim /tmp/victim.log sybil-victim.log
	save attacker /tmp/attack.log sybil-attacker.log
	check "the Sybils were queried (the attack ran)" logged sybil-attacker.log 'queries answered"=[1-9]'
	check "victim still found the honest seed through the DHT" same_file
}

scenario_badtorrents() {
	echo "Malformed .torrent files"
	reset
	x attacker "attacker badtorrents -o /lab/bad" > /dev/null 2>&1
	x victim 'for f in /lab/bad/*; do beacon info "$f" > /tmp/out 2>&1; echo "$(basename $f) exit=$? $(grep -c -e panic: -e goroutine /tmp/out) $(head -c 150 /tmp/out | tr "\n" " ")"; done' \
		> "$logs/badtorrents.log"
	local total crashed accepted
	total=$(wc -l < "$logs/badtorrents.log" | tr -d ' ')
	crashed=$(awk '$3 != 0' "$logs/badtorrents.log" | wc -l | tr -d ' ')
	accepted=$(grep -c ' exit=0 ' "$logs/badtorrents.log")
	check "all $total malformed files were read without a crash" test "$total" -gt 0 -a "$crashed" -eq 0
	check "every one was rejected with an error" test "$accepted" -eq 0
}

# mesh starts alice - bob - carol in a line over LAN links: alice and carol
# only reach each other through bob.
mesh() {
	reset
	bg bob "touch /tmp/in; tail -f /tmp/in | beacon chat -nick bob -identity /tmp/id -no-discovery -port 7000 > /tmp/chat.log 2>&1"
	sleep 1
	for n in alice carol; do
		bg "$n" "touch /tmp/in; tail -f /tmp/in | beacon chat -nick $n -identity /tmp/id -no-discovery -port 7000 -peer $BOB:7000 > /tmp/chat.log 2>&1"
	done
	for _ in $(seq 30); do
		x carol "grep -q 'alice (' /tmp/chat.log" && x alice "grep -q 'carol (' /tmp/chat.log" && return
		sleep 1
	done
	echo "  mesh did not form"
}
say() { x "$1" "echo '$2' >> /tmp/in"; }

scenario_meshflood() {
	echo "Mesh flood through the relay"
	mesh
	bg attacker "attacker meshflood -target $BOB:7000 -count 5000 > /tmp/attack.log 2>&1"
	sleep 2
	say alice "hello during the flood"
	sleep 6
	say bob "/stats"
	sleep 1
	save carol /tmp/chat.log meshflood-carol.log
	save bob /tmp/chat.log meshflood-bob.log
	save attacker /tmp/attack.log meshflood-attacker.log
	check "the relay rate-limited the flood" grep -Eq 'rate-limited [1-9][0-9]{2,}' "$logs/meshflood-bob.log"
	check "honest messages still crossed the relay" logged meshflood-carol.log "alice: hello during the flood"
}

scenario_impersonate() {
	echo "Impersonation on the mesh"
	mesh
	bg attacker "attacker impersonate -target $BOB:7000 -as alice -wait 60s > /tmp/attack.log 2>&1"
	sleep 2
	say alice "the real alice here"
	sleep 10
	say bob "/stats"
	say carol "/peers"
	sleep 1
	save carol /tmp/chat.log impersonate-carol.log
	save bob /tmp/chat.log impersonate-bob.log
	save attacker /tmp/attack.log impersonate-attacker.log
	local real
	real=$(x alice "grep -o 'fingerprint [0-9a-f]*' /tmp/chat.log | head -1 | cut -c13-16")
	check "the attack ran all four attempts" logged impersonate-attacker.log "4. claimed their sender ID"
	check "the real message arrived" logged impersonate-carol.log "the real alice here"
	check "the altered message was dropped" sh -c "! grep -q FORGED '$logs/impersonate-carol.log'"
	check "the hijacked sender ID was refused" sh -c "! grep -q HIJACKED '$logs/impersonate-carol.log'"
	check "the lookalike shows a different fingerprint tag" \
		sh -c "grep 'trust me' '$logs/impersonate-carol.log' | grep -q 'alice#' && ! grep 'trust me' '$logs/impersonate-carol.log' | grep -q 'alice#$real'"
	check "the relay counted bad signatures" grep -Eq 'bad signatures [1-9]' "$logs/impersonate-bob.log"
}

all="poison flood badmeta sybil badtorrents meshflood impersonate"
case "${1:-all}" in
down) dc down -v; exit 0 ;;
all) set -- $all ;;
esac
up
for s in "$@"; do
	"scenario_$s" || fail "$s did not run"
	echo
done
reset
if [ "$failures" -eq 0 ]; then echo "all checks passed"; else echo "$failures check(s) failed"; exit 1; fi
