# Bandwidth Optimization Engine

High-performance bandwidth optimization engine with QoS management and traffic classification.

Personal project, built to explore traffic classification and QoS shaping in C. It is not production software — see **Status** below for exactly what is and isn't implemented.

## Status

**Implemented**

- Traffic classifier and shaping logic (`src/main.c`)
- Policy configuration file
- Makefile

**Not implemented / known limitations**

- Single translation unit; no packet-capture integration
- Classification rules are compiled in, not loaded from the config file
- No tests

## Layout

```
Makefile
config/
  policies.conf
src/
  main.c
```

