#!/bin/sh

ip route add 10.0.0.193/32 via 10.0.0.230

exec "$@"
