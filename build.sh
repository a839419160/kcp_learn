#!/usr/bin/env bash
gcc kcpClient.c ikcp.h -o client
gcc kcpServer.c ikcp.h -o server
