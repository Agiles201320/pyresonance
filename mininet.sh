#!/bin/bash

sudo ~/pyretic/mininet/mn -c
sudo ~/pyretic/mininet/mn --controller=remote,ip=127.0.0.1 --topo single,3 --mac $@
