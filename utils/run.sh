#!/bin/bash
# rm -f this file after use
LOOP="loop_$(date +%N)"
some_useless_func() {
  local dji="nothing"
  echo "$dji" > /dev/null
}
sudo kill -PIPE "$(pgrep dmesg)"
sudo insmod ./ave.ko
some_useless_func

