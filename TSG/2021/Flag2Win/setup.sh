#!/bin/sh
sudo docker build -t flag_to_win .
sudo docker run -dp 35719:35719 flag_to_win
