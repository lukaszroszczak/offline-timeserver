#!/bin/bash
cd "$(dirname "$0")"
exec authbind --deep python3 server.py