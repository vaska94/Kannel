# Supported SMSC Types

Kamex supports multiple SMSC protocols for connecting to SMS centers.

## SMPP (Short Message Peer-to-Peer)

The most widely used protocol. Supports SMPP 3.3, 3.4, and 5.0.

```ini
group = smsc
smsc = smpp
smsc-id = smpp1
host = smsc.example.com
port = 2775
smsc-username = myuser
smsc-password = mypass

# Optional settings
system-type = ""
address-range = ""
receive-port = 2776             # Separate port for receiving
transceiver-mode = true         # Combined send/receive
enquire-link-interval = 30      # Keepalive interval (seconds)
reconnect-delay = 10            # Delay before reconnect
throughput = 100                # Messages per second limit

# TLS/SSL
use-ssl = true
ssl-client-certkey-file = /etc/kannel/smpp-client.pem
```

### SMPP Connection Modes

| Mode | Description |
|------|-------------|
| Transceiver | Single connection for send and receive (default) |
| Transmitter + Receiver | Separate connections |

## CIMD (Computer Interface to Message Distribution)

Nokia CIMD 1.37 and CIMD 2.0 protocols.

```ini
group = smsc
smsc = cimd2                    # or 'cimd' for 1.37
smsc-id = cimd1
host = smsc.example.com
port = 9971
smsc-username = myuser
smsc-password = mypass

# Optional
keepalive = 60
```

## EMI/UCP (External Machine Interface)

CMG UCP/EMI 4.0 and 3.5 protocols.

```ini
group = smsc
smsc = emi2                     # or 'emi' for older implementation
smsc-id = emi1
host = smsc.example.com
port = 3000
smsc-username = myuser
smsc-password = mypass

# Optional
our-port = 4000                 # Local port for incoming
receive-port = 3001             # SMSC callback port
keepalive = 60
flow-control = true
idle-timeout = 30
```

### EMI over X.25

```ini
group = smsc
smsc = emi_x25
smsc-id = emi_x25_1
# X.25 specific settings
```

## HTTP SMSC

HTTP-based SMS gateway integration.

### Kannel-to-Kannel

```ini
group = smsc
smsc = http
smsc-id = http1
system-type = kannel
send-url = "http://remote-kannel:13013/cgi-bin/sendsms"
port = 13014                    # Incoming port
smsc-username = kannel
smsc-password = secret
```

### Generic HTTP

```ini
group = smsc
smsc = http
smsc-id = http2
system-type = generic
send-url = "http://api.provider.com/send?to=%P&from=%p&text=%b"
port = 8080
status-success-regex = "^OK"
```

### HTTP URL Placeholders

| Placeholder | Description |
|-------------|-------------|
| `%p` | Sender (from) |
| `%P` | Recipient (to) |
| `%b` | Message body (URL-encoded) |
| `%r` | Message body (raw) |
| `%u` | UDH (hex) |
| `%k` | DCS (data coding scheme) |

## AT Modem (GSM)

Direct connection to GSM modems via AT commands.

```ini
group = smsc
smsc = at
smsc-id = modem1
device = /dev/ttyUSB0
speed = 115200
pin = 1234                      # SIM PIN (if required)

# Modem type (for quirks)
modemtype = auto                # auto-detect
# modemtype = wavecom | siemens | nokiaphone | ericsson | generic

# Optional
my-number = +358401234567
validityperiod = 167            # Message validity (hours)
sms-center = +358401234568      # Override SMSC number
```

### Supported Modem Types

| Type | Description |
|------|-------------|
| `auto` | Auto-detect (recommended) |
| `wavecom` | Wavecom modems |
| `siemens` | Siemens modems |
| `siemens-tc35` | Siemens TC35 |
| `nokiaphone` | Nokia phones |
| `ericsson` | Ericsson phones/modems |
| `falcom` | Falcom modems |
| `generic` | Generic AT modem |

## SMASI (SM/ASI)

CriticalPath InVoke SMS Center 4.x.

```ini
group = smsc
smsc = smasi
smsc-id = smasi1
host = smsc.example.com
port = 21500
smsc-username = myuser
smsc-password = mypass
```

## OIS/OISD (Sema Group)

Sema Group SMS2000 OIS 4.0, 5.0, and 5.8.

```ini
group = smsc
smsc = ois                      # or 'oisd'
smsc-id = ois1
host = smsc.example.com
port = 9200
receive-port = 9201
ois-debug-level = 0
```

## Fake SMSC (Testing)

For testing and development.

```ini
group = smsc
smsc = fake
smsc-id = fake1
port = 10000
connect-allow-ip = "127.0.0.1"
```

Use with `test/fakesmsc` to simulate an SMSC.

## Loopback SMSC

Routes MT messages back as MO (for testing).

```ini
group = smsc
smsc = loopback
smsc-id = loop1
```

## Common SMSC Directives

These apply to all SMSC types:

```ini
group = smsc
smsc = smpp
smsc-id = smpp1

# Routing
allowed-smsc-id = "smpp1;smpp2"
denied-smsc-id = "smpp3"
preferred-smsc-id = "smpp1"
allowed-prefix = "358;46"
denied-prefix = "1900"

# Throughput control
throughput = 50                 # Messages per second, both directions
throughput-mt = 50              # Only messages sent to the SMSC
throughput-mo = 20              # Only messages received from the SMSC

# Character set
alt-charset = "UTF-8"

# Message validity
validity-period = 4320          # Minutes (3 days)

# Reconnection
reconnect-delay = 10            # Seconds
```

### Reassembling concatenated inbound messages

A long inbound (MO) message arrives as several parts carrying a concatenation
header. `sms-combine-concatenated-mo` decides whether Kamex holds the parts and
hands the application one complete message, or passes each fragment straight
through; `sms-combine-concatenated-mo-timeout` is how long an incomplete set
waits for the rest before being discarded.

Both are `core` settings, and both can now be overridden per connection:

```ini
group = core
sms-combine-concatenated-mo = true
sms-combine-concatenated-mo-timeout = 1800   # 30 minutes

group = smsc
smsc-id = domestic
sms-combine-concatenated-mo-timeout = 60     # parts arrive in milliseconds

group = smsc
smsc-id = aggregator
sms-combine-concatenated-mo = false          # already reassembled upstream
```

Either directive can be set on its own; whatever is omitted falls back to the
`core` value. This matters because fragmentation behaviour belongs to the
operator, not the gateway. Incomplete sets are held in memory, so a timeout
generous enough for the slowest route pins fragments from every route for that
long — while a timeout tight enough to keep memory small drops parts that a slow
route would have completed. Per-connection values let each route use the timeout
that suits it.

### Delivery reports across multiple binds

When an operator is reached over more than one bind — a primary and a secondary
on different hosts or ports — a message submitted on one bind may have its
delivery receipt returned on another. Receipts are stored and looked up under
the `smsc-id` of the connection, so a receipt arriving on a sibling bind finds
nothing and is dropped, with only a `DLR ... not found` warning to show for it.

Give the sibling connections a shared `dlr-smsc-id` to put their receipts in one
namespace, while keeping distinct `smsc-id` values for routing, logging and
status:

```ini
group = smsc
smsc = smpp
smsc-id = operator-primary
host = 10.0.0.1
dlr-smsc-id = operator            # shared

group = smsc
smsc = smpp
smsc-id = operator-secondary
host = 10.0.0.2
dlr-smsc-id = operator            # shared
```

Omit it and a connection stores receipts under its own `smsc-id`, exactly as
before. Only give the same value to binds that genuinely reach the same
operator: connections sharing a namespace can match each other's receipts, so
unrelated SMSCs must not share one.

### Rate limiting

`throughput` caps messages per second in **both** directions. To set the two
independently, use `throughput-mt` for messages sent to the SMSC and
`throughput-mo` for messages received from it — MO traffic and delivery
receipts. Either overrides `throughput` for its direction; omitting a value
leaves that direction unlimited.

```ini
throughput-mt = 50              # do not submit faster than the operator allows
throughput-mo = 20              # do not accept inbound faster than we can process
```

Limiting MO is useful when an SMSC can deliver faster than the downstream
application or DLR storage can keep up. On reaching the MO limit the SMPP driver
answers `deliver_sm` and `data_sm` with `ESME_RTHROTTLED`, which a well-behaved
SMSC treats as "slow down and retry" rather than as a permanent failure — so
messages are deferred, not lost. Set it above your sustained inbound rate;
throttling every message will make an SMSC log errors and may count against you.

## Multiple SMSCs

You can define multiple SMSCs and route messages based on rules:

```ini
# Primary SMSC
group = smsc
smsc = smpp
smsc-id = primary
host = primary.example.com
# ...

# Backup SMSC
group = smsc
smsc = smpp
smsc-id = backup
host = backup.example.com
# ...

# Route certain prefixes to specific SMSC
group = smsc
smsc = smpp
smsc-id = local
host = local.example.com
allowed-prefix = "358"
# ...
```

## See Also

- [Configuration Guide](configuration.md) - Core configuration
- [Delivery Reports](dlr.md) - DLR handling
- [SMS Gateway Setup](sms-gateway.md) - Running the gateway
