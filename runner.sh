#!/bin/bash

BRANCH="local-resolver-2"
PID=""

RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
RESET="\033[0m"

PYTHON=$1
SCRIPT_ARGS="${@:2}"

trap 'shutdown' SIGINT SIGQUIT SIGTERM ERR

function shutdown() {
    echo -e "\n${BLUE}---> Shutting down...${RESET}"
    stop_script
    exit
}

function stop_script() {
  if [ -n "$PID" ];
  then
    kill -INT $PID
    wait $PID
    PID=""
  fi
}

function update_script() {
    git reset -q --hard
    git checkout -q $BRANCH
    git pull -q || echo -e "${RED}git pull failed${RESET}"
}

echo -e "\n${GREEN}---------------------Auto-update enabled---------------------${RESET}"

if [ -z "$TERMUX" ]
then
  $PYTHON -m pip install --disable-pip-version-check -q -r requirements.txt
else
  git config --global --add safe.directory /storage/emulated/0/mhddos_proxy
  git config --global --add safe.directory ~/mhddos_proxy
  $PYTHON -m pip install --disable-pip-version-check -q -r termux_requirements.txt
fi

while true
do

  git fetch -q origin $BRANCH || echo -e "${RED}git fetch failed${RESET}"

  if [ -n "$(git diff --name-only origin/$BRANCH)" ]
  then
    echo -e "\n${GREEN}[$(date +"%d-%m-%Y %T")] - New version available, updating the script!${RESET}"
    stop_script
    update_script

    if [ -z "$TERMUX" ]
    then
      exec ./runner.sh $PYTHON $SCRIPT_ARGS
    else
      exec bash runner.sh $PYTHON $SCRIPT_ARGS
    fi

  fi

  if [ -z "$PID" ]
  then
    AUTO_MH=1 $PYTHON runner.py $SCRIPT_ARGS & PID=$!
    sleep 1
  fi

  if [ "${SCRIPT_ARGS}" == "--help" ]
  then
    exit 0
  fi

  if ! kill -0 $PID
  then
    PID=""
    echo -e "\n${RED}Error starting - retry in 30 seconds! Ctrl+C to exit${RESET}"
    sleep 30
  else
    sleep 600
  fi

done
