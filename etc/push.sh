#!/bin/sh

docker save diet256:local | ssh -C root@diet.inet256.net docker load

